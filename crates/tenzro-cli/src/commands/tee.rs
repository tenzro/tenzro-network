//! TEE (Trusted Execution Environment) commands for the Tenzro CLI
//!
//! Detect TEE hardware, get and verify attestations, and list providers.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// TEE operations
#[derive(Debug, Subcommand)]
pub enum TeeCommand {
    /// Detect available TEE hardware on this node
    Detect(TeeDetectCmd),
    /// Get a TEE attestation quote
    Attest(TeeAttestCmd),
    /// Get a single-use nonce an attestation report must answer
    Challenge(TeeChallengeCmd),
    /// Verify a TEE attestation report against a nonce from `challenge`
    Verify(TeeVerifyCmd),
    /// List registered TEE providers on the network
    Providers(TeeProvidersCmd),
}

impl TeeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Detect(cmd) => cmd.execute().await,
            Self::Attest(cmd) => cmd.execute().await,
            Self::Challenge(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
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

        let available = result
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if available {
            output::print_success("TEE hardware detected!");
            output::print_field(
                "Provider",
                result
                    .get("provider")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
            );
            output::print_field(
                "Type",
                result
                    .get("tee_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
            );
        } else {
            output::print_warning("No TEE hardware detected. Simulation mode available.");
        }

        Ok(())
    }
}

/// Get TEE attestation
#[derive(Debug, Parser)]
pub struct TeeAttestCmd {
    /// Hex data the report commits to (64 zero bytes when omitted)
    #[arg(long)]
    user_data: Option<String>,
    /// Write the report (JSON, as `tee verify --report` takes its hex) to this file
    #[arg(long)]
    out: Option<std::path::PathBuf>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeAttestCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("TEE Attestation");
        let spinner = output::create_spinner("Getting attestation...");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(d) = &self.user_data {
            params["user_data"] = serde_json::Value::from(d.as_str());
        }
        let result: serde_json::Value = rpc.call("tenzro_getTeeAttestation", params).await?;
        spinner.finish_and_clear();

        let field = |k: &str| {
            result
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        output::print_success("Attestation retrieved!");
        output::print_field("Vendor", &field("vendor"));
        output::print_field("Report data", &field("user_data_hex"));
        for m in result
            .get("measurements")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            output::print_field(
                m.get("register").and_then(|v| v.as_str()).unwrap_or(""),
                m.get("value_hex").and_then(|v| v.as_str()).unwrap_or(""),
            );
        }
        if let Some(path) = &self.out {
            let hex_report = field("report_hex");
            let bytes = hex::decode(hex_report.trim_start_matches("0x"))?;
            std::fs::write(path, bytes)?;
            output::print_field("Report written to", &path.display().to_string());
        }
        Ok(())
    }
}

/// Get an attestation nonce
#[derive(Debug, Parser)]
pub struct TeeChallengeCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TeeChallengeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_teeAttestationChallenge", serde_json::json!({}))
            .await?;
        output::print_field(
            "Nonce",
            result.get("nonce").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Expires in (s)",
            &result
                .get("expires_in_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        Ok(())
    }
}

/// Verify TEE attestation
#[derive(Debug, Parser)]
pub struct TeeVerifyCmd {
    /// Hex of the JSON attestation report, including its vendor collateral
    #[arg(long)]
    report: String,
    /// The nonce from `tenzro tee challenge` the report answers
    #[arg(long)]
    nonce: String,
    /// Hex of any extra data the report binds alongside the nonce
    #[arg(long)]
    bound_data: Option<String>,
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

        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyTeeAttestation",
                serde_json::json!({
                    "report_hex": self.report,
                    "nonce": self.nonce,
                    "bound_data": self.bound_data,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        let valid = result
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if valid {
            output::print_success("Attestation is valid!");
            for field in ["vendor", "measurement_hex", "tcb_status"] {
                if let Some(v) = result.get(field).and_then(|v| v.as_str()) {
                    output::print_field(field, v);
                }
            }
            for m in result
                .get("measurements")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                output::print_field(
                    m.get("register").and_then(|v| v.as_str()).unwrap_or(""),
                    m.get("value_hex").and_then(|v| v.as_str()).unwrap_or(""),
                );
            }
        } else {
            output::print_error(&format!(
                "Attestation verification failed: {}",
                result
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            ));
        }

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

        let result: serde_json::Value = rpc
            .call("tenzro_listTeeProviders", serde_json::json!([]))
            .await?;

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
