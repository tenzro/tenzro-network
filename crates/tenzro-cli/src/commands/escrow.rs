//! Escrow and payment channel commands for the Tenzro CLI
//!
//! Manage on-chain escrow accounts and the payment channels opened over them.
//!
//! Escrow create / release / refund are consensus-mediated typed transactions
//! (`TransactionType::CreateEscrow`, `ReleaseEscrow`, `RefundEscrow`) signed
//! by the payer. Create signs with the payer's client keys (`--key-namespace`)
//! and submits pre-signed with `tenzro_sendRawTransaction`.
//! Funds are locked in a deterministically-derived vault address by the Native
//! VM; only the original payer can release or refund.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Escrow and payment channel commands
#[derive(Debug, Subcommand)]
pub enum EscrowCommand {
    #[command(flatten)]
    Rpc(EscrowRpcCommand),
    /// Create a new on-chain escrow (signed CreateEscrow transaction)
    Create(EscrowCreateCmd),
    /// Release escrowed funds to the payee (signed ReleaseEscrow transaction)
    Release(EscrowReleaseCmd),
    /// Refund escrowed funds back to the payer (signed RefundEscrow transaction)
    Refund(EscrowRefundCmd),
    /// Inspect an escrow record by id
    Get(EscrowGetCmd),
    /// Redeem a sealed delivery: the node claims the hash-locked escrows and publishes the key
    RedeemDelivery(RedeemDeliveryCmd),
    /// Read the bond behind a usage meter's key
    MeterBond(MeterBondCmd),
    /// Open a payment channel over a funded escrow
    OpenChannel(ChannelOpenCmd),
    /// Pay on a payment channel with the payer's next cumulative voucher
    Voucher(ChannelVoucherCmd),
    /// Close a payment channel (payer-signed)
    CloseChannel(ChannelCloseCmd),
}

impl EscrowCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Create(cmd) => cmd.execute().await,
            Self::Release(cmd) => cmd.execute().await,
            Self::Refund(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::RedeemDelivery(cmd) => cmd.execute().await,
            Self::MeterBond(cmd) => cmd.execute().await,
            Self::OpenChannel(cmd) => cmd.execute().await,
            Self::Voucher(cmd) => cmd.execute().await,
            Self::CloseChannel(cmd) => cmd.execute().await,
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

fn parse_escrow_id(s: &str) -> Result<[u8; 32]> {
    let clean = s.trim_start_matches("0x");
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("invalid escrow_id hex: {}", e))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "escrow_id must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The release conditions `--release <kind>` names, as the node parses them.
fn release_conditions(
    kind: &str,
    rate_per_epoch: Option<u128>,
    epoch_ms: u64,
    executor: Option<[u8; 32]>,
    payer: [u8; 32],
) -> Result<serde_json::Value> {
    Ok(match kind.to_lowercase().as_str() {
        "timeout" => serde_json::json!("Timeout"),
        "provider" => serde_json::json!("ProviderSignature"),
        "consumer" => serde_json::json!("ConsumerSignature"),
        "both" => serde_json::json!("BothSignatures"),
        "custom" => serde_json::json!({ "Custom": { "condition": "" } }),
        // Released by the named executor, or by the payer when none is named,
        // before expiry; refundable to the payer after it.
        "executor" => serde_json::json!({ "Executor": { "executor": executor.unwrap_or(payer) } }),
        "stream" => serde_json::json!({
            "Stream": {
                "rate_per_epoch": rate_per_epoch.unwrap_or_default().to_string(),
                "epoch_ms": epoch_ms,
            }
        }),
        other => anyhow::bail!(
            "unsupported release condition kind '{}': use timeout|provider|consumer|both|custom|stream|executor",
            other
        ),
    })
}

/// The `CreateEscrow` transaction payload, as the node parses it into
/// `TransactionType::CreateEscrow`: the payee is the 32-byte address.
fn create_escrow_tx(
    payee: [u8; 32],
    amount: u128,
    asset: &str,
    expires_at: u64,
    release_conditions: serde_json::Value,
    reference: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "CreateEscrow": {
            "payee": payee,
            "amount": amount.to_string(),
            "asset_id": asset,
            "expires_at": expires_at,
            "release_conditions": release_conditions,
            "reference": reference,
        }
    })
}

/// Create a new escrow (signed CreateEscrow transaction).
#[derive(Debug, Parser)]
pub struct EscrowCreateCmd {
    /// The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client
    /// account that funds the escrow and signs the transaction.
    #[arg(long, default_value = "client")]
    key_namespace: String,

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

    /// Release condition kind: timeout | provider | consumer | both | custom
    /// | stream (pays the payee per elapsed epoch: a compute rental or a standby)
    /// | executor (released by `--executor`, or by the payer, before expiry)
    #[arg(long, default_value = "timeout")]
    release: String,

    /// For `--release executor`: the account (32-byte hex) that may release
    /// the escrow besides the payer; the payer alone when omitted
    #[arg(long)]
    executor: Option<String>,

    /// For `--release stream`: wei paid per elapsed epoch
    #[arg(long, required_if_eq("release", "stream"))]
    rate_per_epoch: Option<u128>,

    /// For `--release stream`: the epoch length, ms
    #[arg(long, default_value_t = 60 * 60 * 1000)]
    epoch_ms: u64,

    /// An opaque reference the escrow carries (32-byte hex), so the
    /// application that opens it can find it again
    #[arg(long)]
    reference: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Escrow");

        let (payer, _) = crate::keystore::client_account(&self.key_namespace)?;
        let executor = self
            .executor
            .as_deref()
            .map(crate::keystore::address32)
            .transpose()?;
        let release_conditions = release_conditions(
            &self.release,
            self.rate_per_epoch,
            self.epoch_ms,
            executor,
            crate::keystore::address32(&payer)?,
        )?;
        let reference = match &self.reference {
            Some(r) => Some(hex::encode(parse_escrow_id(r)?)),
            None => None,
        };

        let rpc = RpcClient::new(&self.rpc);

        let payee = crate::keystore::address32(&self.payee)?;
        let spinner = output::create_spinner("Querying nonce...");
        // The escrow id is derived from the payer and the nonce the
        // transaction takes, which send_as_client asks the node for in the
        // same way.
        let nonce = crate::rpc::fetch_nonce(&rpc, &payer).await?;
        spinner.set_message("Signing CreateEscrow transaction...");

        let tx_type = create_escrow_tx(
            payee,
            self.amount,
            &self.asset,
            self.expires_at,
            release_conditions,
            reference,
        );

        // Signed as the payer's client account; the VM ignores `to` for a
        // typed escrow transaction and derives the vault.
        let result = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            payee,
            tx_type,
            DEFAULT_ESCROW_CREATE_GAS,
        )
        .await?;
        let escrow_id = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"tenzro/escrow/id");
            h.update(crate::keystore::address32(&payer)?);
            h.update(nonce.to_le_bytes());
            hex::encode(h.finalize())
        };

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
        output::print_field("Payer", &payer);
        output::print_field("Payee", &self.payee);
        output::print_field("Amount (wei)", &self.amount.to_string());
        output::print_field("Asset", &self.asset);
        output::print_field("Expires at (ms)", &self.expires_at.to_string());
        output::print_field("Release", &self.release);
        output::print_field("Transaction Hash", &tx_hash);
        output::print_field("Escrow id", &format!("0x{escrow_id}"));
        println!();
        output::print_warning(
            "Use `tenzro-cli escrow get <escrow_id>` once the transaction executes.",
        );

        Ok(())
    }
}

/// Release an escrow (signed ReleaseEscrow transaction).
#[derive(Debug, Parser)]
pub struct EscrowReleaseCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Payer address (must match the signing key)
    #[arg(long)]
    payer: String,

    /// Escrow id (32-byte hex, with or without 0x prefix)
    escrow_id: String,

    /// Optional proof data (hex). If omitted, an empty proof is used: the
    /// release transaction signed from your own account is your authorisation,
    /// all that any kind but a custom or quorum escrow asks.
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

        let spinner = output::create_spinner("Preparing transaction...");
        spinner.set_message("Signing ReleaseEscrow transaction...");

        let tx_type = serde_json::json!({
            "ReleaseEscrow": {
                "escrow_id": escrow_id_bytes.to_vec(),
                "proof": {
                    "proof_type": "Cryptographic",
                    "proof_data": proof_data,
                    "signatures": [],
                    "attestation": null
                }
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            tx_type,
            DEFAULT_ESCROW_RELEASE_GAS,
        )
        .await?;

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
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

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

        let spinner = output::create_spinner("Preparing transaction...");
        spinner.set_message("Signing RefundEscrow transaction...");

        let tx_type = serde_json::json!({
            "RefundEscrow": { "escrow_id": escrow_id_bytes.to_vec() }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            tx_type,
            DEFAULT_ESCROW_REFUND_GAS,
        )
        .await?;

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
            .call(
                "tenzro_getEscrow",
                serde_json::json!({ "escrow_id": escrow_id_hex }),
            )
            .await?;

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// Redeem a sealed delivery the node offered.
#[derive(Debug, Parser)]
pub struct RedeemDeliveryCmd {
    /// The HashLock escrow paying the node's payee (32-byte hex)
    #[arg(long)]
    escrow_id: String,

    /// The HashLock escrow paying the network's share under the same lock (32-byte hex)
    #[arg(long)]
    network_escrow_id: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RedeemDeliveryCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Redeem Sealed Delivery");
        let rpc = RpcClient::new(&self.rpc);
        let hex_id =
            |s: &str| -> Result<String> { Ok(format!("0x{}", hex::encode(parse_escrow_id(s)?))) };
        let mut params = serde_json::json!({ "escrow_id": hex_id(&self.escrow_id)? });
        if let Some(n) = &self.network_escrow_id {
            params["network_escrow_id"] = serde_json::Value::String(hex_id(n)?);
        }
        let result: serde_json::Value = rpc.call("tenzro_redeemSealedDelivery", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Read the bond behind a usage meter.
#[derive(Debug, Parser)]
pub struct MeterBondCmd {
    /// The meter id: the account slot of its P-256 key (32-byte hex)
    meter_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MeterBondCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Meter Bond");
        let rpc = RpcClient::new(&self.rpc);
        let key = format!("0x{}", hex::encode(parse_escrow_id(&self.meter_id)?));
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getMeterBond",
                serde_json::json!({ "meter_id": key }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Pay `charge` on a payment channel. The payer signs a voucher for the
/// channel's new cumulative total with its client keys; the node accepts it
/// only if the escrow on chain covers it. With `--out` the signed voucher is
/// written to a file instead, for a call that carries it as its
/// `channel_voucher` and is charged its metered cost against it.
#[derive(Debug, Parser)]
pub struct ChannelVoucherCmd {
    /// Channel id (the escrow id, 32-byte hex)
    channel_id: String,

    /// The channel's cumulative total after this payment, in wei
    #[arg(long)]
    cumulative: u128,

    /// What this payment pays, in wei (the increase over the last voucher)
    #[arg(long, required_unless_present = "out")]
    charge: Option<u128>,

    /// Write the signed voucher to this file as JSON and pay nothing now
    #[arg(long, conflicts_with = "charge")]
    out: Option<std::path::PathBuf>,

    /// The head of the receipt chain this voucher pays for (32 bytes of
    /// hex); omit for a voucher signed ahead of delivery
    #[arg(long)]
    binding: Option<String>,

    /// The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client
    /// account that funded the escrow.
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChannelVoucherCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Pay on Payment Channel");
        let escrow_id = parse_escrow_id(&self.channel_id)?;
        let rpc = RpcClient::new(&self.rpc);
        let chain_id = rpc
            .call::<serde_json::Value>("eth_chainId", serde_json::json!([]))
            .await?
            .as_str()
            .map(crate::rpc::parse_hex_u64)
            .ok_or_else(|| anyhow::anyhow!("eth_chainId returned no chain id"))?;
        let binding = match &self.binding {
            Some(h) => parse_escrow_id(h)?,
            None => [0u8; 32],
        };
        let voucher = crate::keystore::sign_voucher(
            &self.key_namespace,
            chain_id,
            escrow_id,
            self.cumulative,
            binding,
        )?;
        let Some(charge) = self.charge else {
            let out = self
                .out
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("pass --charge or --out"))?;
            std::fs::write(out, serde_json::to_vec_pretty(&voucher)?)
                .map_err(|e| anyhow::anyhow!("write {}: {e}", out.display()))?;
            output::print_success("Voucher signed");
            println!();
            output::print_field("Channel ID", &format!("0x{}", hex::encode(escrow_id)));
            output::print_field("Cumulative (wei)", &self.cumulative.to_string());
            output::print_field("Written", &out.display().to_string());
            return Ok(());
        };
        let result: serde_json::Value = rpc
            .call(
                "tenzro_updatePaymentChannel",
                serde_json::json!({ "voucher": voucher, "charge": charge.to_string() }),
            )
            .await?;

        output::print_success("Voucher accepted");
        println!();
        output::print_field("Channel ID", &format!("0x{}", hex::encode(escrow_id)));
        output::print_field("Cumulative (wei)", &self.cumulative.to_string());
        output::print_field("Charge (wei)", &charge.to_string());
        if let Some(r) = result.get("reference").and_then(|v| v.as_str()) {
            output::print_field("Reference", r);
        }
        Ok(())
    }
}

/// Open a payment channel over an escrow the payer already funded (with
/// `tenzro escrow create`) naming the node's payee.
#[derive(Debug, Parser)]
pub struct ChannelOpenCmd {
    /// The funded escrow's id (32-byte hex): the channel id
    #[arg(long)]
    channel_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChannelOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Open Payment Channel");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_openPaymentChannel",
                serde_json::json!({ "channel_id": self.channel_id }),
            )
            .await?;

        output::print_success("Payment channel open");
        println!();
        output::print_field("Channel ID", &self.channel_id);
        for key in ["payer", "deposit", "state"] {
            if let Some(v) = result.get(key) {
                output::print_field(key, v.to_string().trim_matches('"'));
            }
        }
        Ok(())
    }
}

/// Close a payment channel. The payer signs the request with its client
/// keys; the node then claims the highest voucher on-chain.
#[derive(Debug, Parser)]
pub struct ChannelCloseCmd {
    /// Channel id (the escrow id, 32-byte hex)
    channel_id: String,

    /// The payer's hardware key namespace (a-z, 0-9, '-', '_'): the client
    /// account that funded the escrow.
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ChannelCloseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Close Payment Channel");
        let escrow_id = parse_escrow_id(&self.channel_id)?;
        let mut params = crate::keystore::sign_owner_request(
            &self.key_namespace,
            "tenzro_closePaymentChannel",
            &escrow_id,
        )?;
        params.insert("channel_id".into(), hex::encode(escrow_id).into());
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_closePaymentChannel",
                serde_json::Value::Object(params),
            )
            .await?;

        output::print_success("Payment channel closing");
        println!();
        output::print_field("Channel ID", &self.channel_id);
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }
        if let Some(v) = result.get("claim_due").and_then(|v| v.as_str()) {
            output::print_field("Claim due (wei)", v);
        }
        Ok(())
    }
}

/// Escrow commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum EscrowRpcCommand {
    /// Call tenzro_listEscrowsByPayee (list escrows by payee) and print the node's answer
    ByPayee(EscrowByPayeeRpcCmd),
    /// Call tenzro_listEscrowsByPayer (list escrows by payer) and print the node's answer
    ByPayer(EscrowByPayerRpcCmd),
}

impl EscrowRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::ByPayee(cmd) => cmd.execute().await,
            Self::ByPayer(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_listEscrowsByPayee (list escrows by payee)
#[derive(Debug, clap::Parser)]
pub struct EscrowByPayeeRpcCmd {
    /// payee
    #[arg(long)]
    payee: String,
    /// cursor
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowByPayeeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listEscrowsByPayee",
                serde_json::json!({ "payee": self.payee, "cursor": self.cursor }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listEscrowsByPayer (list escrows by payer)
#[derive(Debug, clap::Parser)]
pub struct EscrowByPayerRpcCmd {
    /// payer
    #[arg(long)]
    payer: String,
    /// cursor
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EscrowByPayerRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listEscrowsByPayer",
                serde_json::json!({ "payer": self.payer, "cursor": self.cursor }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

#[cfg(test)]
mod create_escrow_payload_tests {
    use super::create_escrow_tx;

    #[test]
    fn the_payload_parses_as_the_create_escrow_transaction() {
        let tx = create_escrow_tx(
            [0x1f; 32],
            10_000_000_000_000_000,
            "TNZO",
            1_800_000_000_000,
            serde_json::json!("ProviderSignature"),
            None,
        );
        let parsed: tenzro_types::transaction::TransactionType =
            serde_json::from_value(tx).expect("the node parses the payload");
        match parsed {
            tenzro_types::transaction::TransactionType::CreateEscrow { payee, amount, .. } => {
                assert_eq!(payee.as_bytes(), &[0x1f; 32]);
                assert_eq!(amount, 10_000_000_000_000_000);
            }
            other => panic!("parsed as {other:?}"),
        }
    }
}

#[cfg(test)]
mod release_conditions_tests {
    use super::release_conditions;
    use tenzro_types::settlement::ReleaseConditions;

    fn parsed(kind: &str, executor: Option<[u8; 32]>, payer: [u8; 32]) -> ReleaseConditions {
        let value = release_conditions(kind, None, 60_000, executor, payer).expect("a known kind");
        serde_json::from_value(value).expect("the node parses the release conditions")
    }

    #[test]
    fn an_executor_escrow_names_the_account_that_releases_it() {
        match parsed("executor", Some([0x2a; 32]), [0x11; 32]) {
            ReleaseConditions::Executor { executor } => {
                assert_eq!(executor.as_bytes(), &[0x2a; 32])
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn an_executor_escrow_without_an_executor_is_released_by_its_payer() {
        match parsed("executor", None, [0x11; 32]) {
            ReleaseConditions::Executor { executor } => {
                assert_eq!(executor.as_bytes(), &[0x11; 32])
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn the_signature_kinds_parse_as_before() {
        assert_eq!(parsed("timeout", None, [0; 32]), ReleaseConditions::Timeout);
        assert_eq!(
            parsed("consumer", None, [0; 32]),
            ReleaseConditions::ConsumerSignature
        );
    }
}
