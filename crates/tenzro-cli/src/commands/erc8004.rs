//! ERC-8004 Trustless Agents Registry commands.
//!
//! Builds calldata for the IdentityRegistry, ReputationRegistry, and
//! ValidationRegistry contracts, and derives canonical `agentId` from
//! a Tenzro DID.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// ERC-8004 Trustless Agents Registry operations
#[derive(Debug, Subcommand)]
pub enum Erc8004Command {
    /// Derive canonical agentId (keccak256(did)) from a DID
    DeriveId(DeriveAgentIdCmd),
    /// Build calldata for registerAgent(bytes32, address, string)
    EncodeRegister(EncodeRegisterCmd),
    /// Build calldata for getAgent(bytes32)
    EncodeGet(EncodeGetAgentCmd),
    /// Decode the ABI return of getAgent()
    DecodeGet(DecodeGetAgentCmd),
    /// Build calldata for submitFeedback(bytes32, int8, string)
    EncodeFeedback(EncodeFeedbackCmd),
    /// Build calldata for requestValidation(bytes32, bytes32, string)
    EncodeRequestValidation(EncodeRequestValidationCmd),
    /// Build calldata for submitValidation(bytes32, bool, string)
    EncodeSubmitValidation(EncodeSubmitValidationCmd),
}

impl Erc8004Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::DeriveId(cmd) => cmd.execute().await,
            Self::EncodeRegister(cmd) => cmd.execute().await,
            Self::EncodeGet(cmd) => cmd.execute().await,
            Self::DecodeGet(cmd) => cmd.execute().await,
            Self::EncodeFeedback(cmd) => cmd.execute().await,
            Self::EncodeRequestValidation(cmd) => cmd.execute().await,
            Self::EncodeSubmitValidation(cmd) => cmd.execute().await,
        }
    }
}

/// Derive agent id from DID
#[derive(Debug, Parser)]
pub struct DeriveAgentIdCmd {
    /// Tenzro DID (e.g. did:tenzro:machine:...)
    #[arg(long)]
    did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DeriveAgentIdCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Derive ERC-8004 Agent ID");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004DeriveAgentId",
                serde_json::json!({ "did": self.did }),
            )
            .await?;
        output::print_field(
            "DID",
            result.get("did").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Agent ID (bytes32)",
            result.get("agent_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode registerAgent calldata
#[derive(Debug, Parser)]
pub struct EncodeRegisterCmd {
    /// Tenzro DID to register
    #[arg(long)]
    did: String,
    /// 20-byte EVM address of the agent
    #[arg(long)]
    agent_address: String,
    /// Optional metadata URI (e.g. https://...)
    #[arg(long, default_value = "")]
    metadata_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 registerAgent");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeRegister",
                serde_json::json!({
                    "did": self.did,
                    "agent_address": self.agent_address,
                    "metadata_uri": self.metadata_uri,
                }),
            )
            .await?;
        output::print_field(
            "Agent ID",
            result.get("agent_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode getAgent calldata
#[derive(Debug, Parser)]
pub struct EncodeGetAgentCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetAgentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getAgent");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetAgent",
                serde_json::json!({ "agent_id": self.agent_id }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Decode getAgent return data
#[derive(Debug, Parser)]
pub struct DecodeGetAgentCmd {
    /// ABI-encoded return data (0x-prefixed hex)
    #[arg(long)]
    return_data: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DecodeGetAgentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Decode ERC-8004 getAgent Return");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004DecodeGetAgent",
                serde_json::json!({ "return_data": self.return_data }),
            )
            .await?;
        output::print_field(
            "Agent Address",
            result.get("agent_address").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Metadata URI",
            result.get("metadata_uri").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode submitFeedback calldata
#[derive(Debug, Parser)]
pub struct EncodeFeedbackCmd {
    /// Subject agent id (0x-prefixed bytes32)
    #[arg(long)]
    subject_agent_id: String,
    /// Rating in range [-128, 127]
    #[arg(long)]
    rating: i64,
    /// Optional feedback context URI
    #[arg(long, default_value = "")]
    context_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeFeedbackCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 submitFeedback");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeFeedback",
                serde_json::json!({
                    "subject_agent_id": self.subject_agent_id,
                    "rating": self.rating,
                    "context_uri": self.context_uri,
                }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode requestValidation calldata
#[derive(Debug, Parser)]
pub struct EncodeRequestValidationCmd {
    /// Subject agent id (0x-prefixed bytes32)
    #[arg(long)]
    subject_agent_id: String,
    /// Work hash (0x-prefixed bytes32)
    #[arg(long)]
    work_hash: String,
    /// Optional metadata URI
    #[arg(long, default_value = "")]
    metadata_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeRequestValidationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 requestValidation");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeRequestValidation",
                serde_json::json!({
                    "subject_agent_id": self.subject_agent_id,
                    "work_hash": self.work_hash,
                    "metadata_uri": self.metadata_uri,
                }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode submitValidation calldata
#[derive(Debug, Parser)]
pub struct EncodeSubmitValidationCmd {
    /// Request id (0x-prefixed bytes32)
    #[arg(long)]
    request_id: String,
    /// Whether the validation passed
    #[arg(long)]
    valid: bool,
    /// Optional proof URI
    #[arg(long, default_value = "")]
    proof_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeSubmitValidationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 submitValidation");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeSubmitValidation",
                serde_json::json!({
                    "request_id": self.request_id,
                    "valid": self.valid,
                    "proof_uri": self.proof_uri,
                }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}
