//! AgentBond surety commands for the Tenzro CLI.
//!
//! Bonds let a controller (or an autonomous machine) post TNZO as
//! "skin in the game" so the agent's actions are insurable. An Active
//! bond ≥ `bond_min_for_promotion` promotes a Machine identity into
//! the Delegated admission lane even when its controller is unknown
//! or sub-Enhanced KYC.
//!
//! Posting / increasing / withdrawing a bond are consensus-mediated
//! typed transactions (`PostAgentBond`, `IncreaseAgentBond`,
//! `WithdrawAgentBond`) signed with the controller's Ed25519 key and
//! submitted via `tenzro_sendRawTransaction`. Reads
//! (`tenzro_getAgentBond`, `tenzro_listAgentBondsByController`) hit the
//! the bond records in chain state.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// AgentBond surety commands
#[derive(Debug, Subcommand)]
pub enum BondCommand {
    /// Post a new AgentBond (signed PostAgentBond transaction)
    Post(BondPostCmd),
    /// Increase an existing AgentBond (signed IncreaseAgentBond transaction)
    Increase(BondIncreaseCmd),
    /// Initiate cooldown / withdrawal of an AgentBond (signed WithdrawAgentBond transaction)
    Withdraw(BondWithdrawCmd),
    /// Inspect a single AgentBond by agent DID (read-only)
    Get(BondGetCmd),
    /// List AgentBonds by controller DID (read-only)
    List(BondListCmd),
}

impl BondCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Post(cmd) => cmd.execute().await,
            Self::Increase(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
        }
    }
}

use tenzro_types::constants::bond_gas::{
    AGENT_BOND_INCREASE as DEFAULT_BOND_INCREASE_GAS, AGENT_BOND_POST as DEFAULT_BOND_POST_GAS,
    AGENT_BOND_WITHDRAW as DEFAULT_BOND_WITHDRAW_GAS,
};

fn extract_tx_hash(result: &serde_json::Value) -> String {
    result
        .get("tx_hash")
        .or_else(|| result.get("transaction_hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| result.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Post a new AgentBond.
#[derive(Debug, Parser)]
pub struct BondPostCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Agent DID (e.g. `did:tenzro:machine:...`) the bond is posted against
    #[arg(long)]
    agent_did: String,

    /// Controller DID (e.g. `did:tenzro:human:...`)
    #[arg(long)]
    controller_did: String,

    /// Bond amount in wei (1 TNZO = 10^18 wei)
    #[arg(long)]
    amount: u128,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondPostCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Post AgentBond");

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        spinner.set_message("Signing PostAgentBond transaction...");

        let tx_type = serde_json::json!({
            "PostAgentBond": {
                "agent_did": self.agent_did,
                "controller_did": self.controller_did,
                "amount": self.amount.to_string(),
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            tx_type,
            DEFAULT_BOND_POST_GAS,
        )
        .await?;

        spinner.finish_and_clear();

        output::print_success("PostAgentBond transaction submitted");
        println!();
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Controller DID", &self.controller_did);
        output::print_field("Amount (wei)", &self.amount.to_string());
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        Ok(())
    }
}

/// Increase an existing AgentBond.
#[derive(Debug, Parser)]
pub struct BondIncreaseCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Agent DID whose bond is being increased
    #[arg(long)]
    agent_did: String,

    /// Additional bond amount in wei
    #[arg(long)]
    amount: u128,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondIncreaseCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Increase AgentBond");

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        spinner.set_message("Signing IncreaseAgentBond transaction...");

        let tx_type = serde_json::json!({
            "IncreaseAgentBond": {
                "agent_did": self.agent_did,
                "amount": self.amount.to_string(),
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            tx_type,
            DEFAULT_BOND_INCREASE_GAS,
        )
        .await?;

        spinner.finish_and_clear();

        output::print_success("IncreaseAgentBond transaction submitted");
        println!();
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Additional Amount (wei)", &self.amount.to_string());
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        Ok(())
    }
}

/// Initiate the cooldown / withdrawal of an AgentBond.
#[derive(Debug, Parser)]
pub struct BondWithdrawCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Agent DID whose bond is being withdrawn
    #[arg(long)]
    agent_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Withdraw AgentBond");

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Querying nonce and chain ID...");
        spinner.set_message("Signing WithdrawAgentBond transaction...");

        let tx_type = serde_json::json!({
            "WithdrawAgentBond": {
                "agent_did": self.agent_did,
            }
        });

        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            tx_type,
            DEFAULT_BOND_WITHDRAW_GAS,
        )
        .await?;

        spinner.finish_and_clear();

        output::print_success("WithdrawAgentBond transaction submitted (cooldown started)");
        println!();
        output::print_field("Agent DID", &self.agent_did);
        output::print_field("Transaction Hash", &extract_tx_hash(&result));
        output::print_warning(
            "Bond enters Cooldown lifecycle; principal returns to controller after \
             the configured cooldown window finalizes.",
        );
        Ok(())
    }
}

/// Inspect a single AgentBond by agent DID.
#[derive(Debug, Parser)]
pub struct BondGetCmd {
    /// Agent DID
    agent_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("AgentBond Details");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getAgentBond",
                serde_json::json!({ "agent_did": self.agent_did }),
            )
            .await?;

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// List AgentBonds for a given controller.
#[derive(Debug, Parser)]
pub struct BondListCmd {
    /// Controller DID
    controller_did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("AgentBonds by Controller");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listAgentBondsByController",
                serde_json::json!({ "controller_did": self.controller_did }),
            )
            .await?;

        println!();
        let bonds = result
            .get("bonds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if bonds.is_empty() {
            output::print_warning("No bonds found for this controller.");
            return Ok(());
        }

        for (i, bond) in bonds.iter().enumerate() {
            println!("Bond #{}", i + 1);
            for (key, val) in bond.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }

        if let Some(agg) = result.get("aggregate_bond").and_then(|v| v.as_str()) {
            output::print_field("Aggregate Bond (promotion-eligible, wei)", agg);
        }

        Ok(())
    }
}
