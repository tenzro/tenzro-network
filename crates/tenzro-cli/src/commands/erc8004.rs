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
    /// Build calldata for validationRequest(address,uint256,string,bytes32) per ERC-8004
    EncodeValidationRequest(EncodeValidationRequestCmd),
    /// Build calldata for validationResponse(bytes32,uint8,string,bytes32,string) per ERC-8004
    EncodeValidationResponse(EncodeValidationResponseCmd),
    /// Build calldata for setAgentURI(uint256, string) per ERC-8004 v0.6+
    EncodeSetAgentUri(EncodeSetAgentUriCmd),
    /// Build calldata for setAgentWallet(uint256, address, uint256, bytes) per ERC-8004 v0.6+
    EncodeSetAgentWallet(EncodeSetAgentWalletCmd),
    /// Build calldata for setMetadata(uint256, string, bytes) per ERC-8004 v0.6+
    EncodeSetMetadata(EncodeSetMetadataCmd),
    /// Build calldata for getMetadata(uint256, string) per ERC-8004 v0.6+
    EncodeGetMetadata(EncodeGetMetadataCmd),
    /// Decode the ABI return of getMetadata()
    DecodeGetMetadata(DecodeGetMetadataCmd),
    /// Build calldata for getAgentURI(uint256) per ERC-8004 v0.6+
    EncodeGetAgentUri(EncodeGetAgentUriCmd),
    /// Build calldata for getAgentWallet(uint256) per ERC-8004 v0.6+
    EncodeGetAgentWallet(EncodeGetAgentWalletCmd),
    /// Build calldata for revokeFeedback(uint256, bytes32) per ERC-8004 v0.6+
    EncodeRevokeFeedback(EncodeRevokeFeedbackCmd),
    /// Build calldata for appendResponse(uint256, bytes32, string) per ERC-8004 v0.6+
    EncodeAppendResponse(EncodeAppendResponseCmd),
    /// Build calldata for isFeedbackRevoked(uint256, bytes32) per ERC-8004 v0.6+
    EncodeIsFeedbackRevoked(EncodeIsFeedbackRevokedCmd),
    /// Build calldata for getFeedbackResponses(uint256, bytes32) per ERC-8004 v0.6+
    EncodeGetFeedbackResponses(EncodeGetFeedbackResponsesCmd),
    /// Build calldata for getFeedback(bytes32, uint256)
    EncodeGetFeedback(EncodeGetFeedbackCmd),
    /// Build calldata for getFeedbackCount(bytes32)
    EncodeGetFeedbackCount(EncodeGetFeedbackCountCmd),
    /// Build calldata for getValidation(bytes32)
    EncodeGetValidation(EncodeGetValidationCmd),
}

impl Erc8004Command {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::DeriveId(cmd) => cmd.execute().await,
            Self::EncodeRegister(cmd) => cmd.execute().await,
            Self::EncodeGet(cmd) => cmd.execute().await,
            Self::DecodeGet(cmd) => cmd.execute().await,
            Self::EncodeFeedback(cmd) => cmd.execute().await,
            Self::EncodeValidationRequest(cmd) => cmd.execute().await,
            Self::EncodeValidationResponse(cmd) => cmd.execute().await,
            Self::EncodeSetAgentUri(cmd) => cmd.execute().await,
            Self::EncodeSetAgentWallet(cmd) => cmd.execute().await,
            Self::EncodeSetMetadata(cmd) => cmd.execute().await,
            Self::EncodeGetMetadata(cmd) => cmd.execute().await,
            Self::DecodeGetMetadata(cmd) => cmd.execute().await,
            Self::EncodeGetAgentUri(cmd) => cmd.execute().await,
            Self::EncodeGetAgentWallet(cmd) => cmd.execute().await,
            Self::EncodeRevokeFeedback(cmd) => cmd.execute().await,
            Self::EncodeAppendResponse(cmd) => cmd.execute().await,
            Self::EncodeIsFeedbackRevoked(cmd) => cmd.execute().await,
            Self::EncodeGetFeedbackResponses(cmd) => cmd.execute().await,
            Self::EncodeGetFeedback(cmd) => cmd.execute().await,
            Self::EncodeGetFeedbackCount(cmd) => cmd.execute().await,
            Self::EncodeGetValidation(cmd) => cmd.execute().await,
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

/// Encode validationRequest calldata
/// per ERC-8004 `validationRequest(address,uint256,string,bytes32)`.
#[derive(Debug, Parser)]
pub struct EncodeValidationRequestCmd {
    /// Validator address (0x-prefixed 20-byte EVM address)
    #[arg(long)]
    validator_address: String,
    /// Subject agent id (0x-prefixed bytes32, uint256 word)
    #[arg(long)]
    agent_id: String,
    /// Resolvable URI to the work being validated
    #[arg(long, default_value = "")]
    request_uri: String,
    /// Request hash — 32-byte commitment over the work (0x-prefixed bytes32)
    #[arg(long)]
    request_hash: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeValidationRequestCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 validationRequest");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeValidationRequest",
                serde_json::json!({
                    "validator_address": self.validator_address,
                    "agent_id": self.agent_id,
                    "request_uri": self.request_uri,
                    "request_hash": self.request_hash,
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

/// Encode validationResponse calldata
/// per ERC-8004 `validationResponse(bytes32,uint8,string,bytes32,string)`.
#[derive(Debug, Parser)]
pub struct EncodeValidationResponseCmd {
    /// Request hash from the matching validationRequest (0x-prefixed bytes32)
    #[arg(long)]
    request_hash: String,
    /// Quality score 0..=100
    #[arg(long)]
    response: u8,
    /// Resolvable URI to proof material
    #[arg(long, default_value = "")]
    response_uri: String,
    /// Response hash — 32-byte commitment over the response payload (0x-prefixed bytes32)
    #[arg(long)]
    response_hash: String,
    /// Categorical label (e.g. "valid", "invalid", "abstain")
    #[arg(long, default_value = "")]
    tag: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeValidationResponseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 validationResponse");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeValidationResponse",
                serde_json::json!({
                    "request_hash": self.request_hash,
                    "response": self.response,
                    "response_uri": self.response_uri,
                    "response_hash": self.response_hash,
                    "tag": self.tag,
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

// ---------------------------------------------------------------------
// ERC-8004 v0.6+ identity mutators
// ---------------------------------------------------------------------

/// Encode setAgentURI calldata
#[derive(Debug, Parser)]
pub struct EncodeSetAgentUriCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Updated metadata URI
    #[arg(long, default_value = "")]
    metadata_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeSetAgentUriCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 setAgentURI");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeSetAgentURI",
                serde_json::json!({
                    "agent_id": self.agent_id,
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

/// Encode setAgentWallet calldata
#[derive(Debug, Parser)]
pub struct EncodeSetAgentWalletCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// New wallet address (0x-prefixed 20-byte EVM address)
    #[arg(long)]
    new_wallet: String,
    /// Authorization deadline (uint256, low 64 bits used)
    #[arg(long)]
    deadline: u64,
    /// Authorization signature (0x-prefixed hex)
    #[arg(long)]
    signature: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeSetAgentWalletCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 setAgentWallet");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeSetAgentWallet",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "new_wallet": self.new_wallet,
                    "deadline": self.deadline,
                    "signature": self.signature,
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

/// Encode setMetadata calldata
#[derive(Debug, Parser)]
pub struct EncodeSetMetadataCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Metadata key string
    #[arg(long)]
    metadata_key: String,
    /// Metadata value (0x-prefixed hex bytes)
    #[arg(long)]
    metadata_value: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeSetMetadataCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 setMetadata");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeSetMetadata",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "metadata_key": self.metadata_key,
                    "metadata_value": self.metadata_value,
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

// ---------------------------------------------------------------------
// ERC-8004 v0.6+ identity reads
// ---------------------------------------------------------------------

/// Encode getMetadata calldata
#[derive(Debug, Parser)]
pub struct EncodeGetMetadataCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Metadata key string
    #[arg(long)]
    metadata_key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetMetadataCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getMetadata");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetMetadata",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "metadata_key": self.metadata_key,
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

/// Decode getMetadata return data
#[derive(Debug, Parser)]
pub struct DecodeGetMetadataCmd {
    /// ABI-encoded return data (0x-prefixed hex)
    #[arg(long)]
    return_data: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DecodeGetMetadataCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Decode ERC-8004 getMetadata Return");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004DecodeGetMetadata",
                serde_json::json!({ "return_data": self.return_data }),
            )
            .await?;
        output::print_field(
            "Metadata Value (hex)",
            result.get("metadata_value").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode getAgentURI calldata
#[derive(Debug, Parser)]
pub struct EncodeGetAgentUriCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetAgentUriCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getAgentURI");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetAgentURI",
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

/// Encode getAgentWallet calldata
#[derive(Debug, Parser)]
pub struct EncodeGetAgentWalletCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetAgentWalletCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getAgentWallet");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetAgentWallet",
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

// ---------------------------------------------------------------------
// ERC-8004 v0.6+ reputation mutators / reads
// ---------------------------------------------------------------------

/// Encode revokeFeedback calldata
#[derive(Debug, Parser)]
pub struct EncodeRevokeFeedbackCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Feedback id (0x-prefixed bytes32)
    #[arg(long)]
    feedback_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeRevokeFeedbackCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 revokeFeedback");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeRevokeFeedback",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "feedback_id": self.feedback_id,
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

/// Encode appendResponse calldata
#[derive(Debug, Parser)]
pub struct EncodeAppendResponseCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Feedback id (0x-prefixed bytes32)
    #[arg(long)]
    feedback_id: String,
    /// Response URI (e.g. https://...)
    #[arg(long, default_value = "")]
    response_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeAppendResponseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 appendResponse");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeAppendResponse",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "feedback_id": self.feedback_id,
                    "response_uri": self.response_uri,
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

/// Encode isFeedbackRevoked calldata
#[derive(Debug, Parser)]
pub struct EncodeIsFeedbackRevokedCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Feedback id (0x-prefixed bytes32)
    #[arg(long)]
    feedback_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeIsFeedbackRevokedCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 isFeedbackRevoked");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeIsFeedbackRevoked",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "feedback_id": self.feedback_id,
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

/// Encode getFeedbackResponses calldata
#[derive(Debug, Parser)]
pub struct EncodeGetFeedbackResponsesCmd {
    /// Agent id (0x-prefixed bytes32)
    #[arg(long)]
    agent_id: String,
    /// Feedback id (0x-prefixed bytes32)
    #[arg(long)]
    feedback_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetFeedbackResponsesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getFeedbackResponses");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetFeedbackResponses",
                serde_json::json!({
                    "agent_id": self.agent_id,
                    "feedback_id": self.feedback_id,
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

/// Encode getFeedback calldata
#[derive(Debug, Parser)]
pub struct EncodeGetFeedbackCmd {
    /// Subject agent id (0x-prefixed bytes32)
    #[arg(long)]
    subject_agent_id: String,
    /// Feedback index (uint256)
    #[arg(long)]
    index: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetFeedbackCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getFeedback");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetFeedback",
                serde_json::json!({
                    "subject_agent_id": self.subject_agent_id,
                    "index": self.index,
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

/// Encode getFeedbackCount calldata
#[derive(Debug, Parser)]
pub struct EncodeGetFeedbackCountCmd {
    /// Subject agent id (0x-prefixed bytes32)
    #[arg(long)]
    subject_agent_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetFeedbackCountCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getFeedbackCount");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetFeedbackCount",
                serde_json::json!({ "subject_agent_id": self.subject_agent_id }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

/// Encode getValidation calldata
#[derive(Debug, Parser)]
pub struct EncodeGetValidationCmd {
    /// Request hash from the matching validationRequest (0x-prefixed bytes32)
    #[arg(long)]
    request_hash: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EncodeGetValidationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode ERC-8004 getValidation");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_erc8004EncodeGetValidation",
                serde_json::json!({ "request_hash": self.request_hash }),
            )
            .await?;
        output::print_field(
            "Calldata",
            result.get("calldata").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}
