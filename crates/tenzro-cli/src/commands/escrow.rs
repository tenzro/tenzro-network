//! Escrow and payment channel commands for the Tenzro CLI
//!
//! Manage on-chain escrow accounts and micropayment channels for settlement.
//!
//! Escrow create / release / refund are consensus-mediated typed transactions
//! (`TransactionType::CreateEscrow`, `ReleaseEscrow`, `RefundEscrow`) signed
//! with the payer's Ed25519 key and submitted via `tenzro_signAndSendTransaction`.
//! Funds are locked in a deterministically-derived vault address by the Native
//! VM; only the original payer can release or refund.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Escrow and payment channel commands
#[derive(Debug, Subcommand)]
pub enum EscrowCommand {
    /// Create a new on-chain escrow (signed CreateEscrow transaction)
    Create(EscrowCreateCmd),
    /// Release escrowed funds to the payee (signed ReleaseEscrow transaction)
    Release(EscrowReleaseCmd),
    /// Refund escrowed funds back to the payer (signed RefundEscrow transaction)
    Refund(EscrowRefundCmd),
    /// Inspect an escrow record by id
    Get(EscrowGetCmd),
    /// Open a micropayment channel
    OpenChannel(ChannelOpenCmd),
    /// Close a micropayment channel
    CloseChannel(ChannelCloseCmd),
    /// Delegate voting power to a validator
    Delegate(DelegateCmd),
    /// Settle a payment immediately
    Settle(SettleCmd),
    /// Get settlement details
    GetSettlement(GetSettlementCmd),
}

impl EscrowCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute().await,
            Self::Release(cmd) => cmd.execute().await,
            Self::Refund(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::OpenChannel(cmd) => cmd.execute().await,
            Self::CloseChannel(cmd) => cmd.execute().await,
            Self::Delegate(cmd) => cmd.execute().await,
            Self::Settle(cmd) => cmd.execute().await,
            Self::GetSettlement(cmd) => cmd.execute().await,
        }
    }
}

const DEFAULT_ESCROW_CREATE_GAS: u64 = 75_000;
const DEFAULT_ESCROW_RELEASE_GAS: u64 = 60_000;
const DEFAULT_ESCROW_REFUND_GAS: u64 = 50_000;

// Authentication is ambient: the node identifies the signing wallet from the
// OAuth/DPoP bearer token (TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF env vars,
// forwarded by RpcClient::call). The node enforces that the bearer's
// authorized wallet matches `payer` for every escrow tx-type.

/// Query nonce + chain_id for the sender (defaults if unreachable).
async fn fetch_nonce_and_chain_id(
    rpc: &crate::rpc::RpcClient,
    address: &str,
) -> (u64, u64) {
    let nonce = rpc
        .call::<serde_json::Value>(
            "eth_getTransactionCount",
            serde_json::json!([address, "latest"]),
        )
        .await
        .ok()
        .and_then(|v| {
            v.as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
        .unwrap_or(0);
    let chain_id = rpc
        .call::<serde_json::Value>("eth_chainId", serde_json::json!([]))
        .await
        .ok()
        .and_then(|v| {
            v.as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
        .unwrap_or(1337);
    (nonce, chain_id)
}

fn parse_escrow_id(s: &str) -> Result<[u8; 32]> {
    let clean = s.trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| anyhow::anyhow!("invalid escrow_id hex: {}", e))?;
    if bytes.len() != 32 {
        anyhow::bail!("escrow_id must be 32 bytes (64 hex chars), got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Create a new escrow (signed CreateEscrow transaction).
#[derive(Debug, Parser)]
pub struct EscrowCreateCmd {
    /// Payer address (hex, must match the signing key)
    #[arg(long)]
    payer: String,

    /// Payee address (hex)
    #[arg(long)]
    payee: String,

    /// Amount in wei (smallest unit; 1 TNZO = 10^18 wei)
    #[arg(long)]
    amount: u128,

    /// Asset id (defaults to native TNZO)
    #[arg(long, default_value = "TNZO")]
    asset: String,

    /// Expiry as Unix timestamp in milliseconds
    #[arg(long)]
    expires_at: u64,

    /// Release condition kind: timeout | provider | consumer | both | verifier | custom
    #[arg(long, default_value = "timeout")]
    release: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Escrow");

        let release_conditions = match self.release.to_lowercase().as_str() {
            "timeout" => serde_json::json!({ "type": "Timeout" }),
            "provider" => serde_json::json!({ "type": "ProviderSignature" }),
            "consumer" => serde_json::json!({ "type": "ConsumerSignature" }),
            "both" => serde_json::json!({ "type": "BothSignatures" }),
            "verifier" => serde_json::json!({ "type": "VerifierSignature" }),
            "custom" => serde_json::json!({ "type": "Custom", "data": "" }),
            other => anyhow::bail!(
                "unsupported release condition kind '{}': use timeout|provider|consumer|both|verifier|custom",
                other
            ),
        };

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.payer).await;
        spinner.set_message("Signing CreateEscrow transaction...");

        // The `tx_type` field is parsed server-side as `TransactionType::CreateEscrow`.
        let tx_type = serde_json::json!({
            "type": "CreateEscrow",
            "data": {
                "payee": self.payee,
                "amount": self.amount.to_string(),
                "asset_id": self.asset,
                "expires_at": self.expires_at,
                "release_conditions": release_conditions,
            }
        });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.payer,
                // CreateEscrow has no natural recipient — the VM derives the vault.
                // Pass payee for parity but the VM ignores `tx.to` for typed escrow tx.
                "to": self.payee,
                "value": 0u64,
                "gas_limit": DEFAULT_ESCROW_CREATE_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        output::print_success("CreateEscrow transaction submitted");
        println!();
        output::print_field("Payer", &self.payer);
        output::print_field("Payee", &self.payee);
        output::print_field("Amount (wei)", &self.amount.to_string());
        output::print_field("Asset", &self.asset);
        output::print_field("Expires at (ms)", &self.expires_at.to_string());
        output::print_field("Release", &self.release);
        output::print_field("Transaction Hash", &tx_hash);
        println!();
        output::print_warning(
            "Use `tenzro-cli escrow get <escrow_id>` once the tx finalizes — the \
             escrow_id is logged by the VM (SHA-256 of payer || nonce_le)."
        );

        Ok(())
    }
}

/// Release an escrow (signed ReleaseEscrow transaction).
#[derive(Debug, Parser)]
pub struct EscrowReleaseCmd {
    /// Payer address (must match the signing key)
    #[arg(long)]
    payer: String,

    /// Escrow id (32-byte hex, with or without 0x prefix)
    escrow_id: String,

    /// Optional proof data (hex). If omitted, an empty proof is used (Timeout).
    #[arg(long)]
    proof: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowReleaseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Release Escrow");

        let escrow_id_bytes = parse_escrow_id(&self.escrow_id)?;
        let escrow_id_hex = format!("0x{}", hex::encode(escrow_id_bytes));

        let proof_data: Vec<u8> = match &self.proof {
            Some(p) => hex::decode(p.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("invalid --proof hex: {}", e))?,
            None => Vec::new(),
        };

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.payer).await;
        spinner.set_message("Signing ReleaseEscrow transaction...");

        let tx_type = serde_json::json!({
            "type": "ReleaseEscrow",
            "data": {
                "escrow_id": escrow_id_bytes.to_vec(),
                "proof": {
                    "proof_type": "Timeout",
                    "proof_data": proof_data,
                    "signatures": []
                }
            }
        });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.payer,
                "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "value": 0u64,
                "gas_limit": DEFAULT_ESCROW_RELEASE_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        output::print_success("ReleaseEscrow transaction submitted");
        println!();
        output::print_field("Escrow ID", &escrow_id_hex);
        output::print_field("Transaction Hash", &tx_hash);
        Ok(())
    }
}

/// Refund an escrow (signed RefundEscrow transaction).
#[derive(Debug, Parser)]
pub struct EscrowRefundCmd {
    /// Payer address (must match the signing key)
    #[arg(long)]
    payer: String,

    /// Escrow id (32-byte hex)
    escrow_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowRefundCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Refund Escrow");

        let escrow_id_bytes = parse_escrow_id(&self.escrow_id)?;
        let escrow_id_hex = format!("0x{}", hex::encode(escrow_id_bytes));

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.payer).await;
        spinner.set_message("Signing RefundEscrow transaction...");

        let tx_type = serde_json::json!({
            "type": "RefundEscrow",
            "data": { "escrow_id": escrow_id_bytes.to_vec() }
        });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.payer,
                "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "value": 0u64,
                "gas_limit": DEFAULT_ESCROW_REFUND_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| result.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "<unknown>".to_string());

        output::print_success("RefundEscrow transaction submitted");
        println!();
        output::print_field("Escrow ID", &escrow_id_hex);
        output::print_field("Transaction Hash", &tx_hash);
        Ok(())
    }
}

/// Inspect an escrow by id (read-only).
#[derive(Debug, Parser)]
pub struct EscrowGetCmd {
    /// Escrow id (32-byte hex)
    escrow_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Escrow Details");

        let rpc = RpcClient::new(&self.rpc);
        let escrow_id_bytes = parse_escrow_id(&self.escrow_id)?;
        let escrow_id_hex = format!("0x{}", hex::encode(escrow_id_bytes));

        let result: serde_json::Value = rpc
            .call("tenzro_getEscrow", serde_json::json!({ "escrow_id": escrow_id_hex }))
            .await?;

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// Open a micropayment channel
#[derive(Debug, Parser)]
pub struct ChannelOpenCmd {
    /// Counterparty address (hex, e.g. 0x...)
    #[arg(long)]
    counterparty: String,

    /// Deposit amount in TNZO
    #[arg(long)]
    deposit: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChannelOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Open Payment Channel");

        let spinner = output::create_spinner("Opening channel...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_openPaymentChannel", serde_json::json!({
            "counterparty": self.counterparty,
            "deposit": self.deposit,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Payment channel opened!");
        println!();

        if let Some(v) = result.get("channel_id").and_then(|v| v.as_str()) {
            output::print_field("Channel ID", v);
        }
        output::print_field("Counterparty", &self.counterparty);
        if let Some(v) = result.get("deposit").and_then(|v| v.as_str()) {
            output::print_field("Deposit", &format!("{} TNZO", v));
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}

/// Close a micropayment channel
#[derive(Debug, Parser)]
pub struct ChannelCloseCmd {
    /// Channel ID (UUID)
    channel_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChannelCloseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Close Payment Channel");

        let spinner = output::create_spinner("Closing channel...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_closePaymentChannel", serde_json::json!({
            "channel_id": self.channel_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Payment channel closing!");
        println!();

        output::print_field("Channel ID", &self.channel_id);
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }
        if let Some(balances) = result.get("final_balances") {
            if let Some(v) = balances.get("deposit").and_then(|v| v.as_str()) {
                output::print_field("Total Deposit", &format!("{} wei", v));
            }
            if let Some(v) = balances.get("spent").and_then(|v| v.as_str()) {
                output::print_field("Total Spent", &format!("{} wei", v));
            }
            if let Some(v) = balances.get("remaining").and_then(|v| v.as_str()) {
                output::print_field("Remaining", &format!("{} wei", v));
            }
        }

        Ok(())
    }
}

/// Settle a payment immediately
#[derive(Debug, Parser)]
pub struct SettleCmd {
    /// Payer address (hex)
    #[arg(long)]
    payer: String,

    /// Payee address (hex)
    #[arg(long)]
    payee: String,

    /// Amount in TNZO
    #[arg(long)]
    amount: u64,

    /// Settlement type (immediate, escrow, channel)
    #[arg(long, default_value = "immediate")]
    settlement_type: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SettleCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Settle Payment");

        let spinner = output::create_spinner("Settling payment...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_settle", serde_json::json!([{
            "payer": self.payer,
            "payee": self.payee,
            "amount": self.amount,
            "settlement_type": self.settlement_type,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Settlement completed!");
        println!();

        if let Some(v) = result.get("settlement_id").and_then(|v| v.as_str()) {
            output::print_field("Settlement ID", v);
        }
        output::print_field("Payer", &self.payer);
        output::print_field("Payee", &self.payee);
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", v);
        }

        Ok(())
    }
}

/// Get settlement details
#[derive(Debug, Parser)]
pub struct GetSettlementCmd {
    /// Settlement ID
    settlement_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetSettlementCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Settlement Details");

        let spinner = output::create_spinner("Fetching settlement...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getSettlement", serde_json::json!([self.settlement_id])).await?;

        spinner.finish_and_clear();

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// Delegate voting power to a validator
#[derive(Debug, Parser)]
pub struct DelegateCmd {
    /// Delegator address (your address, hex)
    #[arg(long)]
    from: String,

    /// Delegatee/validator address (hex)
    #[arg(long)]
    to: String,

    /// Amount in TNZO to delegate
    #[arg(long)]
    amount: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DelegateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Delegate Voting Power");

        let spinner = output::create_spinner("Delegating...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_delegateVotingPower", serde_json::json!({
            "delegator": self.from,
            "delegatee": self.to,
            "amount": self.amount,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Voting power delegated!");
        println!();

        output::print_field("Delegator", &self.from);
        output::print_field("Delegatee", &self.to);
        output::print_field("Amount", &format!("{} TNZO", self.amount));
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }

        Ok(())
    }
}
