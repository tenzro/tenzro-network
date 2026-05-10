//! Validator commands for the Tenzro CLI (Dynamic Validator Set, task #413).
//!
//! Permissionless validator join/exit with mandatory hybrid PQ keying. Writes
//! (`RegisterValidator`, `ExitValidator`, `UpdateValidatorMetadata`) are
//! consensus-mediated typed transactions submitted via
//! `tenzro_signAndSendTransaction`. Reads (`tenzro_getValidatorState`,
//! `tenzro_listValidators`, `tenzro_listActiveValidators`) hit the node's
//! in-process `ValidatorRegistry` cache.

use clap::{Parser, Subcommand};
use anyhow::{anyhow, Result};
use crate::output;

/// Validator set commands (Dynamic Validator Set)
#[derive(Debug, Subcommand)]
pub enum ValidatorCommand {
    /// Register a new validator candidate (signed RegisterValidator transaction)
    Register(ValidatorRegisterCmd),
    /// Voluntarily exit the validator set (signed ExitValidator transaction)
    Exit(ValidatorExitCmd),
    /// Update validator metadata / TEE attestation commitment
    UpdateMetadata(ValidatorUpdateMetadataCmd),
    /// Inspect a single validator entry by address (read-only)
    Get(ValidatorGetCmd),
    /// List validators (optionally filter by status) (read-only)
    List(ValidatorListCmd),
    /// List currently-Active validators (read-only)
    ListActive(ValidatorListActiveCmd),
}

impl ValidatorCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Exit(cmd) => cmd.execute().await,
            Self::UpdateMetadata(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::ListActive(cmd) => cmd.execute().await,
        }
    }
}

const DEFAULT_REGISTER_GAS: u64 = 200_000;
const DEFAULT_EXIT_GAS: u64 = 80_000;
const DEFAULT_UPDATE_METADATA_GAS: u64 = 80_000;

/// Decode a 0x-prefixed (or bare) hex string into a fixed-size byte array.
fn hex_to_fixed<const N: usize>(s: &str, label: &str) -> Result<[u8; N]> {
    let trimmed = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow!("invalid hex for {}: {}", label, e))?;
    if bytes.len() != N {
        return Err(anyhow!(
            "{} must be {} bytes ({} hex chars), got {}",
            label,
            N,
            N * 2,
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a 0x-prefixed (or bare) hex string into a variable-length Vec<u8>.
fn hex_to_vec(s: &str, label: &str) -> Result<Vec<u8>> {
    let trimmed = s.trim().trim_start_matches("0x");
    hex::decode(trimmed)
        .map_err(|e| anyhow!("invalid hex for {}: {}", label, e))
}

/// Query nonce + chain_id for the sender.
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

fn extract_tx_hash(result: &serde_json::Value) -> String {
    result
        .get("tx_hash")
        .or_else(|| result.get("transaction_hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| result.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Register a new validator candidate.
///
/// The `RegisterValidator` typed transaction stages the candidate under
/// `PendingActive`; the next epoch boundary admits it (subject to churn budget)
/// and the `EpochManager` activates it `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` after
/// that boundary.
#[derive(Debug, Parser)]
pub struct ValidatorRegisterCmd {
    /// Stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// 32-byte Ed25519 BFT consensus signing public key (hex; with or without 0x prefix)
    #[arg(long)]
    consensus_pubkey: String,

    /// 1952-byte ML-DSA-65 PQ verifying key (hex; FIPS 204)
    #[arg(long)]
    pq_pubkey: String,

    /// Withdrawal address — rewards / unbonded principal settle here (hex; 32 bytes)
    #[arg(long)]
    withdrawal_address: String,

    /// Self-stake committed to the candidate, in wei (1 TNZO = 10^18 wei).
    /// Must be ≥ the registry's `min_self_stake` (default 10,000 TNZO).
    #[arg(long)]
    self_stake: u128,

    /// Optional ≤256-byte off-chain pointer (moniker / website / contact)
    #[arg(long, default_value = "")]
    metadata_uri: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Validator");

        // Validate + decode keys client-side so the user gets a clear error
        // rather than a server-side serde failure.
        let consensus_bytes: [u8; 32] =
            hex_to_fixed(&self.consensus_pubkey, "consensus_pubkey")?;
        let pq_bytes = hex_to_vec(&self.pq_pubkey, "pq_pubkey")?;
        if pq_bytes.len() != 1952 {
            return Err(anyhow!(
                "pq_pubkey must be 1952 bytes (ML-DSA-65 FIPS 204), got {}",
                pq_bytes.len()
            ));
        }
        let withdrawal_bytes: [u8; 32] =
            hex_to_fixed(&self.withdrawal_address, "withdrawal_address")?;

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing RegisterValidator transaction...");

        // The Address / Vec<u8> fields serde-derive to JSON arrays of numbers.
        let tx_type = serde_json::json!({
            "type": "RegisterValidator",
            "data": {
                "consensus_pubkey": consensus_bytes.to_vec(),
                "pq_pubkey": pq_bytes,
                "withdrawal_address": withdrawal_bytes,
                "self_stake": self.self_stake.to_string(),
                "metadata_uri": self.metadata_uri,
            }
        });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.from,
                "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "value": 0u64,
                "gas_limit": DEFAULT_REGISTER_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        output::print_success("RegisterValidator transaction submitted");
        println!();
        output::print_field("From", &self.from);
        output::print_field("Consensus pubkey", &self.consensus_pubkey);
        output::print_field("PQ pubkey (len)", &format!("{} bytes", pq_bytes.len()));
        output::print_field("Withdrawal address", &self.withdrawal_address);
        output::print_field("Self-stake (wei)", &self.self_stake.to_string());
        if !self.metadata_uri.is_empty() {
            output::print_field("Metadata URI", &self.metadata_uri);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Candidate is staged under PendingActive. The next epoch boundary \
             admits it (subject to churn budget); activation is effective \
             ACTIVATION_EFFECTIVE_DELAY_BLOCKS after that boundary."
        );
        Ok(())
    }
}

/// Voluntarily exit the validator set.
#[derive(Debug, Parser)]
pub struct ValidatorExitCmd {
    /// Validator stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorExitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Exit Validator");

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing ExitValidator transaction...");

        // ExitValidator is a unit variant — `data` field omitted entirely.
        let tx_type = serde_json::json!({ "type": "ExitValidator" });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.from,
                "to": self.from,
                "value": 0u64,
                "gas_limit": DEFAULT_EXIT_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        output::print_success("ExitValidator transaction submitted");
        println!();
        output::print_field("From", &self.from);
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Validator transitions to PendingExit. Removal is effective \
             ACTIVATION_EFFECTIVE_DELAY_BLOCKS after the next epoch boundary. \
             Re-registration is blocked for `reentry_cooldown_epochs` (default 4) \
             following voluntary exit."
        );
        Ok(())
    }
}

/// Update validator metadata or TEE attestation commitment.
#[derive(Debug, Parser)]
pub struct ValidatorUpdateMetadataCmd {
    /// Validator stake-owning wallet address (hex; must match the signing key)
    #[arg(long)]
    from: String,

    /// New off-chain pointer (≤256 bytes); omit to skip
    #[arg(long)]
    metadata_uri: Option<String>,

    /// New 32-byte SHA-256 TEE attestation commitment (hex); omit to skip
    #[arg(long)]
    tee_attestation_hash: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorUpdateMetadataCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Update Validator Metadata");

        if self.metadata_uri.is_none() && self.tee_attestation_hash.is_none() {
            return Err(anyhow!(
                "At least one of --metadata-uri or --tee-attestation-hash must be provided"
            ));
        }

        let tee_hash_bytes: Option<[u8; 32]> = match self.tee_attestation_hash.as_deref() {
            Some(hex_s) => Some(hex_to_fixed(hex_s, "tee_attestation_hash")?),
            None => None,
        };

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        let (nonce, chain_id) = fetch_nonce_and_chain_id(&rpc, &self.from).await;
        spinner.set_message("Signing UpdateValidatorMetadata transaction...");

        let mut data = serde_json::Map::new();
        match &self.metadata_uri {
            Some(uri) => data.insert(
                "metadata_uri".to_string(),
                serde_json::Value::String(uri.clone()),
            ),
            None => data.insert("metadata_uri".to_string(), serde_json::Value::Null),
        };
        match tee_hash_bytes {
            Some(arr) => data.insert(
                "tee_attestation_hash".to_string(),
                serde_json::to_value(arr).unwrap(),
            ),
            None => data.insert(
                "tee_attestation_hash".to_string(),
                serde_json::Value::Null,
            ),
        };

        let tx_type = serde_json::json!({
            "type": "UpdateValidatorMetadata",
            "data": serde_json::Value::Object(data),
        });

        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": self.from,
                "to": self.from,
                "value": 0u64,
                "gas_limit": DEFAULT_UPDATE_METADATA_GAS,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
                "tx_type": tx_type,
            }),
        ).await?;

        spinner.finish_and_clear();

        output::print_success("UpdateValidatorMetadata transaction submitted");
        println!();
        output::print_field("From", &self.from);
        if let Some(uri) = &self.metadata_uri {
            output::print_field("Metadata URI", uri);
        }
        if let Some(h) = &self.tee_attestation_hash {
            output::print_field("TEE attestation hash", h);
        }
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        Ok(())
    }
}

/// Inspect a single validator entry by address.
#[derive(Debug, Parser)]
pub struct ValidatorGetCmd {
    /// Validator address (32-byte hex; with or without 0x prefix)
    address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validator Entry");

        // Validate the address format client-side.
        let _: [u8; 32] = hex_to_fixed(&self.address, "address")?;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getValidatorState",
                serde_json::json!({ "address": self.address }),
            )
            .await?;

        println!();
        if result.is_null() {
            output::print_warning("No validator entry found for this address.");
            return Ok(());
        }

        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// List validators (optionally filtered by status).
#[derive(Debug, Parser)]
pub struct ValidatorListCmd {
    /// Filter by status: Active | Candidate | PendingActive | PendingExit | Exited | Jailed
    #[arg(long)]
    status: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Validators");

        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::Map::new();
        if let Some(s) = &self.status {
            params.insert("status".to_string(), serde_json::Value::String(s.clone()));
        }
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listValidators",
                serde_json::Value::Object(params),
            )
            .await?;

        println!();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let validators = result
            .get("validators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        output::print_field("Total", &count.to_string());
        if validators.is_empty() {
            output::print_warning("No validators match the filter.");
            return Ok(());
        }
        println!();
        for (i, v) in validators.iter().enumerate() {
            println!("Validator #{}", i + 1);
            for (key, val) in v.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}

/// List currently-Active validators.
#[derive(Debug, Parser)]
pub struct ValidatorListActiveCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ValidatorListActiveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Active Validators");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listActiveValidators", serde_json::json!({}))
            .await?;

        println!();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let validators = result
            .get("validators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        output::print_field("Active count", &count.to_string());
        if validators.is_empty() {
            output::print_warning("No active validators.");
            return Ok(());
        }
        println!();
        for (i, v) in validators.iter().enumerate() {
            println!("Validator #{}", i + 1);
            for (key, val) in v.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }
        Ok(())
    }
}
