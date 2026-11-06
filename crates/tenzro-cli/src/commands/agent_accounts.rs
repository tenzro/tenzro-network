//! An agent's accounts on other chains: where they are, the grants that
//! bound them, the proofs relayers install on those chains, and the serving
//! node's signature over an action there.
//!
//! The CLI holds no key for any other chain. A relayer submits `sync` and
//! actions there with its own account on that chain; the account refunds it
//! up to the grant's cap.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use crate::output;
use crate::rpc::RpcClient;

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

fn print(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

/// The agent's account on every chain the network configures.
#[derive(Debug, Parser)]
pub struct AccountsCmd {
    /// The agent
    did: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl AccountsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Agent accounts");
        let v: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_agentAccounts",
                serde_json::json!({ "did": self.did }),
            )
            .await?;
        print(&v)
    }
}

/// Ask a serving node to issue a grant on another chain, as the agent (its
/// access token, from `tenzro access sign-in` or TENZRO_BEARER_JWT). The grant uses the agent's daily
/// spend at the rate its terms set for the asset.
#[derive(Debug, Parser)]
pub struct GrantCmd {
    /// The chain, CAIP-2
    #[arg(long)]
    chain: String,
    /// The asset, CAIP-19
    #[arg(long)]
    asset: String,
    /// Most the account may move under the grant, in the asset's smallest unit
    #[arg(long)]
    budget: String,
    /// Most one action may move; defaults to the budget
    #[arg(long)]
    per_action: Option<String>,
    /// How long the grant lives, ms
    #[arg(long, default_value_t = 600_000)]
    ttl_ms: u64,
    /// An allowed target, `target_hex:selector_hex` (repeatable)
    #[arg(long = "target")]
    targets: Vec<String>,
    /// A JSON file with the one action an exact grant allows (target,
    /// selector, amount, relay_refund, data)
    #[arg(long)]
    exact: Option<PathBuf>,
    /// Most a relayer may be refunded per action
    #[arg(long, default_value = "0")]
    relay_fee_max: String,
    /// The controller's step-up approval, JSON (`account`, `nonce`,
    /// `root_public_key` hex, and the composite `signature` over the
    /// challenge a refused attempt returns), when the terms require it
    #[arg(long)]
    step_up: Option<PathBuf>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

fn read_json(path: &PathBuf) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

impl GrantCmd {
    pub async fn execute(&self) -> Result<()> {
        let targets = self
            .targets
            .iter()
            .map(|t| {
                let (target, selector) = t
                    .split_once(':')
                    .context("a target is target_hex:selector_hex")?;
                Ok(serde_json::json!({ "target": target, "selector": selector }))
            })
            .collect::<Result<Vec<_>>>()?;
        let payload_hash = match &self.exact {
            Some(path) => {
                let action: tenzro_types::remote_grant::RemoteAction =
                    serde_json::from_value(read_json(path)?)?;
                Some(hex::encode(tenzro_types::remote_grant::payload_hash(
                    &action,
                )))
            }
            None => None,
        };
        let mut params = serde_json::json!({
            "chain": self.chain,
            "grant": {
                "caip19": self.asset,
                "budget": self.budget,
                "per_action_max": self.per_action.clone().unwrap_or_else(|| self.budget.clone()),
                "ttl_ms": self.ttl_ms,
                "targets": targets,
                "payload_hash": payload_hash,
                "relay_fee_max": self.relay_fee_max,
            },
        });
        if let Some(path) = &self.step_up {
            params["step_up"] = read_json(path)?;
        }
        let rpc = RpcClient::new(&self.rpc);
        output::print_header("Remote grant");
        let v: serde_json::Value = rpc.call("tenzro_requestRemoteGrant", params).await?;
        print(&v)
    }
}

/// The agent's grant on a chain and its state proof under a certified
/// checkpoint's state root.
#[derive(Debug, Parser)]
pub struct GrantProofCmd {
    /// The agent
    did: String,
    /// The chain, CAIP-2
    #[arg(long)]
    chain: String,
    /// The checkpoint; defaults to the latest certified one
    #[arg(long)]
    checkpoint: Option<u64>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl GrantProofCmd {
    async fn fetch(&self) -> Result<serde_json::Value> {
        RpcClient::new(&self.rpc)
            .call(
                "tenzro_getAgentGrantProof",
                serde_json::json!({ "did": self.did, "chain": self.chain, "checkpoint": self.checkpoint }),
            )
            .await
    }

    pub async fn execute(&self) -> Result<()> {
        output::print_header("Grant proof");
        print(&self.fetch().await?)
    }
}

/// What a relayer submits to the account's `sync` on its chain: the
/// checkpoint, the grant bytes and the encoded state proof.
#[derive(Debug, Parser)]
pub struct SyncCmd {
    #[command(flatten)]
    proof: GrantProofCmd,
}

impl SyncCmd {
    pub async fn execute(&self) -> Result<()> {
        let v = self.proof.fetch().await?;
        let grant = v["grant_bytes"]
            .as_str()
            .context("the agent holds no grant on that chain")?;
        output::print_header("Sync");
        output::print_field("Checkpoint", &v["checkpoint"].to_string());
        output::print_field("Grant", grant);
        output::print_field("Proof", v["proof_bytes"].as_str().unwrap_or_default());
        output::print_field("Void", &v["grant"]["void"].to_string());
        Ok(())
    }
}

/// The serving node's signature over one action of the agent's account on
/// another chain, as the agent (its access token). Above the grant's cosign
/// threshold, ask a serving node of another operator too.
#[derive(Debug, Parser)]
pub struct ActCmd {
    /// The chain, CAIP-2
    #[arg(long)]
    chain: String,
    /// The account's next action nonce, read from that chain
    #[arg(long)]
    nonce: u64,
    /// A JSON file with the action: target, selector, amount, relay_refund,
    /// data (hex and decimal strings)
    #[arg(long)]
    action: PathBuf,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl ActCmd {
    pub async fn execute(&self) -> Result<()> {
        let action = read_json(&self.action)?;
        let rpc = RpcClient::new(&self.rpc);
        let signed: serde_json::Value = rpc
            .call(
                "tenzro_signRemoteAction",
                serde_json::json!({ "chain": self.chain, "nonce": self.nonce, "action": action }),
            )
            .await?;
        let did = signed["agent_did"].as_str().unwrap_or_default().to_string();
        let built: serde_json::Value = rpc
            .call(
                "tenzro_buildRemoteAction",
                serde_json::json!({ "did": did, "chain": self.chain, "nonce": self.nonce, "action": action }),
            )
            .await?;
        output::print_header("Remote action");
        print(&serde_json::json!({ "signature": signed, "proofs": built }))
    }
}

/// The consent that makes the agent's account on an EVM chain the
/// `agentWallet` of its ERC-8004 entry: the registry's EIP-712 digest and the
/// `approveHash` action that approves it (sign it with `tenzro agent act`),
/// then the `setAgentWallet` call the entry's owner sends.
#[derive(Debug, Parser)]
pub struct WalletConsentCmd {
    /// The agent DID
    #[arg(long)]
    did: String,
    /// The chain, CAIP-2 (eip155:<id>)
    #[arg(long)]
    chain: String,
    /// The ERC-8004 agentId
    #[arg(long)]
    agent_id: u64,
    /// The address that owns the entry
    #[arg(long)]
    owner: String,
    /// Unix seconds the consent expires (at most 300 s after it is used)
    #[arg(long)]
    deadline: u64,
    /// The identity registry, if not the canonical one
    #[arg(long)]
    registry: Option<String>,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl WalletConsentCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut p = serde_json::json!({
            "did": self.did, "chain": self.chain, "agent_id": self.agent_id,
            "owner": self.owner, "deadline": self.deadline,
        });
        if let Some(r) = &self.registry {
            p["registry"] = serde_json::json!(r);
        }
        let v: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_agentWalletConsent", p)
            .await?;
        output::print_header("ERC-8004 agent wallet consent");
        print(&v)
    }
}

/// Settle one report of an agent's account through its chain's route: a
/// closed grant's unspent budget, an action for the audit trail, or an
/// installed void that pays its relay task. Signed by this client's
/// hardware-held account.
#[derive(Debug, Parser)]
pub struct RelayAgentAccountCmd {
    /// The chain, CAIP-2
    #[arg(long)]
    chain: String,
    /// The agent
    #[arg(long)]
    agent: String,
    /// The route delivery carrying the report, hex
    #[arg(long)]
    delivery: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl RelayAgentAccountCmd {
    pub async fn execute(&self) -> Result<()> {
        let delivery =
            hex::decode(self.delivery.trim_start_matches("0x")).context("delivery is hex")?;
        let gas = super::bridge::relay_gas(delivery.len());
        self.signer
            .send_tx_with_gas(
                tenzro_types::transaction::TransactionType::RemoteGrantSettle {
                    agent_did: self.agent.clone(),
                    chain: self.chain.clone(),
                    delivery,
                },
                "RemoteGrantSettle",
                gas,
            )
            .await
    }
}
