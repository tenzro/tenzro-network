//! Post-quantum hybrid signing helpers for the Tenzro CLI.
//!
//! Surfaces the optional `pq_signature` + `pq_public_key` legs of
//! `tenzro_signAndSendTransaction` so operators can sanity-check that a
//! transaction submitted from this node carries the composite
//! Ed25519 + ML-DSA-65 signature pair that mainnet will require after
//! flag-day cutover (the migration is in flight per the project memory
//! `project_pq_migration`).
//!
//! Subcommands:
//!
//! - `tenzro pq-hybrid info`     — node-side hybrid signer status / available algs
//! - `tenzro pq-hybrid send ...` — submit a hybrid-signed transaction explicitly
//! - `tenzro pq-hybrid inspect <tx_hash>` — show whether a finalized tx carried PQ legs
//!
//! The classical (Ed25519/Secp256k1) leg is always present; the PQ leg is
//! optional today (post-cutover it becomes mandatory). The wire format for
//! composite keys/signatures is the leading-tag-byte format described in
//! `tenzro-zk::tee_integration` and `tenzro-crypto::composite`.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// PQ-hybrid signing helper commands
#[derive(Debug, Subcommand)]
pub enum PqHybridCommand {
    /// Show node-side hybrid signer status
    Info(PqHybridInfoCmd),
    /// Submit a transaction explicitly with hybrid Ed25519 + ML-DSA-65 signatures
    Send(PqHybridSendCmd),
    /// Inspect a finalized transaction's signature legs
    Inspect(PqHybridInspectCmd),
}

impl PqHybridCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::Inspect(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct PqHybridInfoCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PqHybridInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("PQ Hybrid — Signer Info");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_getHybridSignerInfo", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PqHybridSendCmd {
    /// Sending account
    #[arg(long)]
    from: String,

    /// Recipient address
    #[arg(long)]
    to: String,

    /// Value to transfer (wei)
    #[arg(long)]
    value: String,

    /// Optional pre-computed PQ public key (hex, ML-DSA-65 vk = 1952 bytes)
    #[arg(long)]
    pq_public_key: Option<String>,

    /// Optional pre-computed PQ signature (hex, ML-DSA-65 sig = 3309 bytes).
    /// Omit both `--pq-public-key` and `--pq-signature` to ask the node to
    /// sign with its locally-configured hybrid signer.
    #[arg(long)]
    pq_signature: Option<String>,

    /// Gas limit
    #[arg(long, default_value_t = 21_000u64)]
    gas_limit: u64,

    /// Gas price (wei)
    #[arg(long, default_value_t = 1_000_000_000u64)]
    gas_price: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PqHybridSendCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("PQ Hybrid — Send");

        let rpc = RpcClient::new(&self.rpc);

        // Resolve nonce + chain id
        let nonce_hex: String = rpc
            .call("tenzro_getNonce", serde_json::json!([self.from]))
            .await?;
        let chain_hex: String = rpc.call("eth_chainId", serde_json::json!([])).await?;

        let mut tx = serde_json::json!({
            "from": self.from,
            "to": self.to,
            "value": self.value,
            "gas_limit": self.gas_limit,
            "gas_price": self.gas_price,
            "nonce": parse_hex_to_u64(&nonce_hex)?,
            "chain_id": parse_hex_to_u64(&chain_hex)?,
        });

        // Attach PQ legs if the caller pre-computed them; otherwise the node
        // will sign with its locally-configured hybrid signer.
        if let Some(pk) = &self.pq_public_key {
            tx["pq_public_key"] = serde_json::Value::String(pk.clone());
        }
        if let Some(sig) = &self.pq_signature {
            tx["pq_signature"] = serde_json::Value::String(sig.clone());
        }

        let tx_hash: String = rpc.call("tenzro_signAndSendTransaction", tx).await?;
        output::print_success("Submitted");
        output::print_field("tx_hash", &tx_hash);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PqHybridInspectCmd {
    /// Transaction hash
    #[arg(long)]
    tx_hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PqHybridInspectCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("PQ Hybrid — Inspect");
        let rpc = RpcClient::new(&self.rpc);
        let tx: serde_json::Value = rpc
            .call("tenzro_getTransaction", serde_json::json!([self.tx_hash]))
            .await?;

        let has_pq_pk = tx.get("pq_public_key").is_some();
        let has_pq_sig = tx.get("pq_signature").is_some();
        output::print_field("classical_signature_present", "true");
        output::print_field("pq_public_key_present", &has_pq_pk.to_string());
        output::print_field("pq_signature_present", &has_pq_sig.to_string());
        if !has_pq_pk || !has_pq_sig {
            output::print_warning(
                "Tx is classical-only — post-cutover, mainnet will reject this shape.",
            );
        }
        println!("{}", serde_json::to_string_pretty(&tx)?);
        Ok(())
    }
}

fn parse_hex_to_u64(s: &str) -> Result<u64> {
    let trimmed = s.trim_start_matches("0x");
    u64::from_str_radix(trimmed, 16).map_err(|e| anyhow::anyhow!("parse hex: {e}"))
}
