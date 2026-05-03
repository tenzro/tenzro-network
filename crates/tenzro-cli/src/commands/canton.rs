//! Canton/DAML integration commands for the Tenzro CLI
//!
//! Interact with Canton domains and DAML smart contracts on the Tenzro Network.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Canton/DAML integration commands
#[derive(Debug, Subcommand)]
pub enum CantonCommand {
    /// List Canton domains
    Domains(CantonDomainsCmd),
    /// List DAML contracts
    Contracts(CantonContractsCmd),
    /// Submit a DAML command
    Submit(CantonSubmitCmd),
}

impl CantonCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Domains(cmd) => cmd.execute().await,
            Self::Contracts(cmd) => cmd.execute().await,
            Self::Submit(cmd) => cmd.execute().await,
        }
    }
}

/// List Canton domains
#[derive(Debug, Parser)]
pub struct CantonDomainsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CantonDomainsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Canton Domains");

        let spinner = output::create_spinner("Loading domains...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listCantonDomains", serde_json::json!([])).await?;

        spinner.finish_and_clear();

        let enabled = result.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
        output::print_field("Canton Enabled", if enabled { "Yes" } else { "No" });

        if !enabled {
            if let Some(msg) = result.get("message").and_then(|v| v.as_str()) {
                output::print_info(msg);
            }
            return Ok(());
        }

        if let Some(domains) = result.get("domains").and_then(|v| v.as_array()) {
            if domains.is_empty() {
                output::print_info("No Canton domains configured.");
            } else {
                let headers = vec!["Domain ID", "Host", "Port", "Status"];
                let mut rows = Vec::new();
                for domain in domains {
                    rows.push(vec![
                        domain.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        domain.get("host").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        domain.get("port").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default(),
                        domain.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// List DAML contracts
#[derive(Debug, Parser)]
pub struct CantonContractsCmd {
    /// Filter by template ID
    #[arg(long)]
    template: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CantonContractsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("DAML Contracts");

        let spinner = output::create_spinner("Loading contracts...");

        let rpc = RpcClient::new(&self.rpc);

        let params = if let Some(template) = &self.template {
            serde_json::json!({ "template_id": template })
        } else {
            serde_json::json!({})
        };

        let result: serde_json::Value = rpc.call("tenzro_listDamlContracts", params).await?;

        spinner.finish_and_clear();

        if let Some(filter) = result.get("filter").and_then(|v| v.as_str()) {
            if !filter.is_empty() {
                output::print_field("Filter", filter);
            }
        }

        if let Some(host) = result.get("canton_host").and_then(|v| v.as_str()) {
            output::print_field("Canton Host", host);
        }
        if let Some(port) = result.get("canton_port").and_then(|v| v.as_u64()) {
            output::print_field("Canton Port", &port.to_string());
        }

        if let Some(contracts) = result.get("contracts").and_then(|v| v.as_array()) {
            if contracts.is_empty() {
                output::print_info("No DAML contracts found.");
            } else {
                let headers = vec!["Contract ID", "Template", "Party", "Status"];
                let mut rows = Vec::new();
                for contract in contracts {
                    rows.push(vec![
                        contract.get("contract_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        contract.get("template_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        contract.get("party").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        contract.get("status").and_then(|v| v.as_str()).unwrap_or("active").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
                println!("Total: {} contracts", contracts.len());
            }
        }

        Ok(())
    }
}

/// Submit a DAML command
#[derive(Debug, Parser)]
pub struct CantonSubmitCmd {
    /// Command type: create, exercise, or exercise_by_key
    #[arg(long)]
    command_type: String,

    /// Template ID
    #[arg(long)]
    template: Option<String>,

    /// Executing party
    #[arg(long)]
    party: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CantonSubmitCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Submit DAML Command");

        let spinner = output::create_spinner("Submitting command...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_submitDamlCommand", serde_json::json!({
            "command_type": self.command_type,
            "template_id": self.template.as_deref().unwrap_or(""),
            "party": self.party.as_deref().unwrap_or(""),
        })).await?;

        spinner.finish_and_clear();

        let submitted = result.get("submitted").and_then(|v| v.as_bool()).unwrap_or(false);
        if submitted {
            output::print_success("DAML command submitted!");
        } else {
            output::print_error("Command submission failed.");
        }
        println!();

        output::print_field("Command Type", &self.command_type);
        if let Some(t) = &self.template {
            output::print_field("Template ID", t);
        }
        if let Some(p) = &self.party {
            output::print_field("Party", p);
        }
        if let Some(host) = result.get("canton_host").and_then(|v| v.as_str()) {
            output::print_field("Canton Host", host);
        }
        if let Some(note) = result.get("note").and_then(|v| v.as_str()) {
            output::print_field("Note", note);
        }

        Ok(())
    }
}
