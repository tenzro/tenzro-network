//! Agent spend, read from consensus.
//!
//! A delegated agent's authority to pay is its consensus Terms; what it has
//! spent against them is consensus state. `tenzro_getAgentTerms` reads
//! both.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Reads a delegated agent's spend against its Terms.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let agent_payments = client.agent_payments();
/// if let Some(view) = agent_payments.get_terms("did:tenzro:agent:abc").await? {
///     println!("{} root, spent today: {}", view.root_kind, view.spent.today);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AgentPaymentClient {
    rpc: Arc<RpcClient>,
}

impl AgentPaymentClient {
    /// Creates a new agent payment client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The agent's full Terms, root kind, status and spend so far against
    /// each limit. `None` when the DID has no Terms on chain.
    pub async fn get_terms(&self, agent_did: &str) -> SdkResult<Option<AgentTermsView>> {
        self.rpc
            .call(
                "tenzro_getAgentTerms",
                serde_json::json!({ "agent_did": agent_did }),
            )
            .await
    }
}

/// A delegated agent's consensus Terms and what it has spent against them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTermsView {
    /// DID of the agent.
    pub agent_did: String,
    /// What approved the Terms: `passkey` (a person) or `machine` (a TPM or
    /// Secure Enclave key).
    pub root_kind: String,
    /// `active`, `quarantined`, `revoked` or `expired`.
    pub status: String,
    /// Increments with every approved change.
    pub version: u64,
    /// Digest of the custody challenge the root approved, hex.
    pub approval_digest: String,
    /// Block time of the last change, ms.
    pub updated_at_ms: i64,
    /// The Terms exactly as chain state records them.
    pub terms: serde_json::Value,
    /// Spend so far against the limits.
    pub spent: AgentSpend,
}

/// What a delegated agent has spent today and this hour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpend {
    /// Spent today, wei, decimal string.
    pub today: String,
    /// Spent this clock hour, wei, decimal string.
    pub this_hour: String,
    /// Actions today.
    pub actions_today: u32,
    /// Actions this clock hour.
    pub actions_this_hour: u32,
    /// What the daily limit leaves, when the Terms set one.
    pub remaining_today: Option<String>,
    /// What the hourly limit leaves, when the Terms set one.
    pub remaining_this_hour: Option<String>,
    /// Per asset limit: spent today and what is left.
    pub assets: Vec<AssetSpend>,
}

/// Spend today in one asset the Terms limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSpend {
    /// The asset id.
    pub asset: String,
    /// Spent today, base units, decimal string.
    pub spent_today: String,
    /// What the asset's daily limit leaves.
    pub remaining_today: Option<String>,
}

impl AgentPaymentClient {
    /// Calls `tenzro_getAgentBond`: get agent bond.
    pub async fn get_agent_bond(
        &self,
        agent_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getAgentBond",
                serde_json::json!({ "agent_did": agent_did }),
            )
            .await
    }

    /// Calls `tenzro_listAgentBondsByController`: list agent bonds by controller.
    pub async fn list_agent_bonds_by_controller(
        &self,
        controller_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_listAgentBondsByController",
                serde_json::json!({ "controller_did": controller_did }),
            )
            .await
    }
}
