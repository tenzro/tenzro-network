//! Transaction inspection.

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};

use crate::output;

/// Transaction commands
#[derive(Debug, Subcommand)]
pub enum TxCommand {
    /// Show what a privileged transaction does and the digest it is signed
    /// over, decoded locally from its typed preimage
    Explain(ExplainCmd),
    /// Ask a node what an unsigned transaction is signed over: the canonical
    /// `tx_type` encoding, or the typed preimage, and the digest
    SigningPayload(SigningPayloadCmd),
}

impl TxCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Explain(cmd) => cmd.execute(),
            Self::SigningPayload(cmd) => cmd.execute().await,
        }
    }
}

/// The signing payload of an unsigned transaction
#[derive(Debug, Parser)]
pub struct SigningPayloadCmd {
    /// The unsigned transaction as `tenzro_sendRawTransaction` takes it (JSON, or
    /// a file holding it), without signatures
    input: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SigningPayloadCmd {
    async fn execute(&self) -> Result<()> {
        let raw = std::fs::read_to_string(&self.input).unwrap_or_else(|_| self.input.clone());
        let params: serde_json::Value =
            serde_json::from_str(raw.trim()).map_err(|e| anyhow!("transaction: {e}"))?;
        let payload: serde_json::Value = crate::rpc::RpcClient::new(&self.rpc)
            .call("tenzro_getSigningPayload", params)
            .await?;
        crate::output::print_json(&payload)
    }
}

/// Decode a typed action
#[derive(Debug, Parser)]
pub struct ExplainCmd {
    /// An unsigned transaction as JSON, or the hex preimage a wallet was
    /// asked to sign
    input: String,
}

impl ExplainCmd {
    fn execute(&self) -> Result<()> {
        use tenzro_types::typed_action::{
            action_preimage, decode_preimage, describe, preimage_digest,
        };
        let raw = std::fs::read_to_string(&self.input).unwrap_or_else(|_| self.input.clone());
        let raw = raw.trim();
        let (preimage, digest) = if raw.starts_with('{') {
            let tx: tenzro_types::transaction::Transaction =
                serde_json::from_str(raw).map_err(|e| anyhow!("transaction: {e}"))?;
            let Some(p) = action_preimage(&tx) else {
                bail!("this transaction exercises no privileged power; it is signed over its hash");
            };
            let digest = preimage_digest(&p);
            (p, digest)
        } else {
            let bytes = hex::decode(raw.trim_start_matches("0x"))?;
            decode_preimage(&bytes).map_err(|e| anyhow!(e))?
        };
        output::print_header("Typed action");
        output::print_field("Class", &serde_json::to_string(&preimage.class)?);
        output::print_field("Signing digest", &hex::encode(digest));
        for line in describe(&preimage) {
            println!("  {line}");
        }
        Ok(())
    }
}
