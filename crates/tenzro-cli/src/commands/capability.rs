//! Capability registry inspection commands.
//!
//! The `CapabilityRegistry` (in `tenzro-agent`) tracks which agents have
//! claimed which capabilities and the signed/TEE-backed attestations
//! supporting those claims. Per CRITICAL #52, every stored attestation
//! has already passed eager Ed25519 signature verification against its
//! canonical signing data, so a returned attestation is — by construction
//! — cryptographically authentic at the moment it was registered.
//!
//! These commands are read-only views over the live registry on a node.
//!
//! Capability strings accepted by `--capability` are the short forms:
//! `nlp`, `vision`, `code`, `data`, `blockchain`, `smart_contract`,
//! `api_integration`, `coordination`. The node also accepts a structured
//! Capability JSON object on the wire, but the CLI is short-string-only.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Capability registry operations.
#[derive(Debug, Subcommand)]
pub enum CapabilityCommand {
    /// List every registered capability with agent + attestation counts.
    List(CapabilityListCmd),

    /// List attestations for a capability (optionally verified-only).
    Attestations(CapabilityAttestationsCmd),

    /// List every attestation issued for a given agent ID.
    AgentAttestations(AgentAttestationsCmd),

    /// Pick the best agent for a capability (TEE-backed preferred).
    BestAgent(BestAgentCmd),
}

impl CapabilityCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Attestations(cmd) => cmd.execute().await,
            Self::AgentAttestations(cmd) => cmd.execute().await,
            Self::BestAgent(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro capability list` — every capability registered on the node,
/// with how many agents claim it and how many signed attestations back
/// those claims. The `rejected_attestation_count` line surfaces the
/// number of attestations the registry has refused since startup
/// (signature mismatch, malformed payload) — a non-zero number is a
/// signal to investigate gossip-layer or attester misbehaviour.
#[derive(Debug, Parser)]
pub struct CapabilityListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CapabilityListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Registered Capabilities");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listCapabilities", serde_json::json!({}))
            .await
            .context("calling tenzro_listCapabilities")?;

        let rejected = result
            .get("rejected_attestation_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        output::print_field("Rejected attestations (since boot)", &rejected.to_string());

        let empty = vec![];
        let entries = result
            .get("capabilities")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);

        if entries.is_empty() {
            output::print_info("No capabilities registered.");
            return Ok(());
        }

        let mut rows: Vec<Vec<String>> = Vec::with_capacity(entries.len());
        for entry in entries {
            let label = entry
                .get("capability")
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            let agents = entry
                .get("agent_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let attestations = entry
                .get("attestation_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            rows.push(vec![label, agents.to_string(), attestations.to_string()]);
        }
        output::print_table(&["Capability", "Agents", "Attestations"], &rows);
        Ok(())
    }
}

/// `tenzro capability attestations --capability <c>` — list attestation
/// envelopes for a capability. Pass `--verified-only` to include only
/// attestations whose signature has been re-verified against the current
/// attester record (in addition to the eager check at registration).
#[derive(Debug, Parser)]
pub struct CapabilityAttestationsCmd {
    /// Short-form capability name: nlp | vision | code | data |
    /// blockchain | smart_contract | api_integration | coordination.
    #[arg(long)]
    capability: String,

    /// Filter to attestations that pass re-verification right now.
    #[arg(long, default_value_t = false)]
    verified_only: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CapabilityAttestationsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("Attestations for {}", self.capability));
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getCapabilityAttestations",
                serde_json::json!({
                    "capability": self.capability,
                    "verified_only": self.verified_only,
                }),
            )
            .await
            .context("calling tenzro_getCapabilityAttestations")?;

        print_attestation_list(&result);
        Ok(())
    }
}

/// `tenzro capability agent-attestations --agent <id>` — every
/// attestation the registry holds about a single agent, across all of
/// its claimed capabilities.
#[derive(Debug, Parser)]
pub struct AgentAttestationsCmd {
    /// Agent ID (the registry key — matches `RegisteredAgent.id`).
    #[arg(long)]
    agent: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AgentAttestationsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("Attestations issued for agent {}", self.agent));
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getAgentCapabilityAttestations",
                serde_json::json!({ "agent_id": self.agent }),
            )
            .await
            .context("calling tenzro_getAgentCapabilityAttestations")?;

        print_attestation_list(&result);
        Ok(())
    }
}

/// `tenzro capability best-agent --capability <c>` — ask the registry
/// for the best agent for a capability. The selection rule is
/// TEE-backed-preferred (any TEE-backed attester beats a non-TEE one);
/// among equals, the registry's deterministic ordering picks the winner.
#[derive(Debug, Parser)]
pub struct BestAgentCmd {
    /// Short-form capability name.
    #[arg(long)]
    capability: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BestAgentCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("Best agent for {}", self.capability));
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_findBestAgentForCapability",
                serde_json::json!({ "capability": self.capability }),
            )
            .await
            .context("calling tenzro_findBestAgentForCapability")?;

        match result.get("agent_id").and_then(|v| v.as_str()) {
            Some(id) if !id.is_empty() => {
                output::print_field("Agent ID", id);
                if let Some(addr) = result.get("attester_address").and_then(|v| v.as_str()) {
                    output::print_field("Attester address", addr);
                }
                if let Some(tee) = result.get("tee_backed").and_then(|v| v.as_bool()) {
                    output::print_field("TEE-backed", if tee { "yes" } else { "no" });
                }
            }
            _ => output::print_info("No agent claims this capability with a valid attestation."),
        }
        Ok(())
    }
}

fn print_attestation_list(result: &serde_json::Value) {
    let empty = vec![];
    let attestations = result
        .get("attestations")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    if attestations.is_empty() {
        output::print_info("No attestations found.");
        return;
    }

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(attestations.len());
    for att in attestations {
        let agent = att
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cap = att
            .get("capability")
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_default();
        let attester = att
            .get("attester_address")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let attested_at = att
            .get("attested_at")
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_default();
        let tee = att
            .get("tee_backed")
            .and_then(|v| v.as_bool())
            .map(|b| if b { "yes" } else { "no" }.to_string())
            .unwrap_or_else(|| "?".to_string());
        rows.push(vec![agent, cap, attester, attested_at, tee]);
    }
    output::print_table(
        &["Agent", "Capability", "Attester", "Attested At", "TEE"],
        &rows,
    );
}
