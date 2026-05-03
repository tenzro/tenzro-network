//! TEE (Trusted Execution Environment) commands for the Tenzro CLI
//!
//! Detect TEE hardware, get attestations, seal/unseal data, and list providers.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// TEE operations
#[derive(Debug, Subcommand)]
pub enum TeeCommand {
    /// Detect available TEE hardware on this node
    Detect(TeeDetectCmd),
    /// Get a TEE attestation quote
    Attest(TeeAttestCmd),
    /// Verify a TEE attestation quote
    Verify(TeeVerifyCmd),
    /// Seal data inside a TEE enclave
    Seal(TeeSealCmd),
    /// Unseal TEE-sealed data
    Unseal(TeeUnsealCmd),
    /// List registered TEE providers on the network
    Providers(TeeProvidersCmd),
}

impl TeeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Detect(cmd) => cmd.execute().await,
            Self::Attest(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Seal(cmd) => cmd.execute().await,
            Self::Unseal(cmd) => cmd.execute().await,
            Self::Providers(cmd) => cmd.execute().await,
        }
    }
}

/// Detect TEE hardware
#[derive(Debug, Parser)]
pub struct TeeDetectCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeDetectCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("TEE Hardware Detection");
        let spinner = output::create_spinner("Detecting TEE hardware...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_detectTee", serde_json::json!([])).await?;

        spinner.finish_and_clear();

        let available = result.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
        if available {
            output::print_success("TEE hardware detected!");
            output::print_field("Provider", result.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown"));
            output::print_field("Type", result.get("tee_type").and_then(|v| v.as_str()).unwrap_or("unknown"));
        } else {
            output::print_warning("No TEE hardware detected. Simulation mode available.");
        }

        Ok(())
    }
}

/// Get TEE attestation
#[derive(Debug, Parser)]
pub struct TeeAttestCmd {
    /// TEE provider: auto, tdx, sev-snp, nitro, gpu
    #[arg(long, default_value = "auto")]
    provider: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeAttestCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("TEE Attestation");
        let spinner = output::create_spinner(&format!("Getting attestation from {}...", self.provider));
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getTeeAttestation", serde_json::json!({
            "provider": self.provider,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Attestation retrieved!");
        output::print_field("Provider", result.get("provider").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Quote", &output::format_hash(result.get("quote_hex").and_then(|v| v.as_str()).unwrap_or("")));

        Ok(())
    }
}

/// Verify TEE attestation
#[derive(Debug, Parser)]
pub struct TeeVerifyCmd {
    /// TEE provider: tdx, sev-snp, nitro, gpu
    #[arg(long)]
    provider: String,
    /// Attestation quote (hex)
    #[arg(long)]
    quote: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify TEE Attestation");
        let spinner = output::create_spinner("Verifying...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_verifyTeeAttestation", serde_json::json!({
            "provider": self.provider,
            "quote_hex": self.quote,
        })).await?;

        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Attestation is valid!");
        } else {
            output::print_error("Attestation verification failed.");
        }

        Ok(())
    }
}

/// Seal data in TEE
#[derive(Debug, Parser)]
pub struct TeeSealCmd {
    /// Plaintext data (hex)
    #[arg(long)]
    data: String,
    /// Key ID for hardware-bound encryption
    #[arg(long)]
    key_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeSealCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Seal Data in TEE");
        let spinner = output::create_spinner("Sealing...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_sealData", serde_json::json!({
            "plaintext_hex": self.data,
            "key_id": self.key_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Data sealed!");
        output::print_field("Ciphertext", result.get("ciphertext_hex").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Unseal TEE data
#[derive(Debug, Parser)]
pub struct TeeUnsealCmd {
    /// Ciphertext (hex)
    #[arg(long)]
    data: String,
    /// Key ID used during sealing
    #[arg(long)]
    key_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeUnsealCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Unseal TEE Data");
        let spinner = output::create_spinner("Unsealing...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_unsealData", serde_json::json!({
            "ciphertext_hex": self.data,
            "key_id": self.key_id,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Data unsealed!");
        output::print_field("Plaintext", result.get("plaintext_hex").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// List TEE providers
#[derive(Debug, Parser)]
pub struct TeeProvidersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeProvidersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("TEE Providers");
        let spinner = output::create_spinner("Fetching providers...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listTeeProviders", serde_json::json!([])).await?;

        spinner.finish_and_clear();

        if let Some(providers) = result.as_array() {
            if providers.is_empty() {
                output::print_info("No TEE providers currently registered.");
            } else {
                for p in providers {
                    let addr = p.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                    let ptype = p.get("tee_type").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    output::print_field(addr, &format!("{} ({})", ptype, status));
                }
            }
        } else {
            output::print_json(&result)?;
        }

        Ok(())
    }
}
