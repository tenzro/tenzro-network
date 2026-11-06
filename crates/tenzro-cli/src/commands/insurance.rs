//! The network insurance pool.
//!
//! The pool is funded by a governed share of fee revenue and by slashed
//! agent bonds. It pays a claim on evidence chain state already holds of a
//! loss a bonded party caused: a proven metered-charge dispute the meter's
//! bond did not cover, an SLA epoch a provider was judged unavailable while a
//! stream paid it, or a settlement-lock mismatch on an attested route.
//!
//! - `tenzro insurance claim` — claim on that evidence (a `PayInsuranceClaim`
//!   transaction signed in hardware as the harmed account)
//! - `tenzro insurance list` — every paid claim (`tenzro_listInsuranceClaims`)
//! - `tenzro insurance get` — one paid claim (`tenzro_getInsuranceClaim`)
//! - `tenzro insurance pool` — the pool's balance, history and claim cap
//!   (`tenzro_getInsurancePoolBalance`)

use crate::output;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tenzro_types::insurance::InsuranceEvidence;
use tenzro_types::transaction::TransactionType;

/// The network insurance pool
#[derive(Debug, Subcommand)]
pub enum InsuranceCommand {
    /// Claim from the pool on a reconciliation mismatch that names you
    Claim(InsuranceClaimCmd),
    /// List every paid claim (read-only)
    List(InsuranceListCmd),
    /// Inspect a paid claim by id (read-only)
    Get(InsuranceGetCmd),
    /// Show the pool's balance, history and claim cap (read-only)
    Pool(InsurancePoolCmd),
}

impl InsuranceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Claim(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::Pool(cmd) => cmd.execute().await,
        }
    }
}

/// Claim from the pool.
#[derive(Debug, Parser)]
pub struct InsuranceClaimCmd {
    /// Bridge protocol of a route whose settlement lock mismatch cost you a
    /// leg (ccip, ibc, deposit or contract)
    #[arg(long, requires_all = ["recon_chain", "recon_position"])]
    recon_adapter: Option<String>,

    /// The route's external chain
    #[arg(long, requires = "recon_adapter")]
    recon_chain: Option<String>,

    /// The mismatch's position in the lock's record
    #[arg(long, requires = "recon_adapter")]
    recon_position: Option<u64>,

    /// The harmed account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow!("{what} is 32 bytes of hex"))
}

impl InsuranceClaimCmd {
    fn evidence(&self) -> Result<InsuranceEvidence> {
        if let (Some(adapter), Some(chain), Some(position)) =
            (&self.recon_adapter, &self.recon_chain, self.recon_position)
        {
            return Ok(InsuranceEvidence::ReconMismatch {
                adapter: serde_json::from_value(serde_json::json!(adapter)).map_err(|_| {
                    anyhow!("--recon-adapter is one of ccip, ibc, deposit, contract")
                })?,
                chain: chain.to_ascii_lowercase(),
                position,
            });
        }
        Err(anyhow!(
            "name the evidence: --recon-adapter <adapter> --recon-chain <chain> --recon-position <n>"
        ))
    }

    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Claim Insurance");
        let rpc = RpcClient::new(&self.rpc);
        let tx_type = serde_json::to_value(TransactionType::PayInsuranceClaim {
            evidence: self.evidence()?,
        })?;
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        let to = hex32(&account, "the client account")?;
        let result =
            crate::keystore::send_as_client(&rpc, &self.key_namespace, to, tx_type, 150_000)
                .await?;
        output::print_success("PayInsuranceClaim signed in hardware and submitted");
        output::print_field("Claimant", &account);
        output::print_field(
            "Tx Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok(())
    }
}

/// List all insurance claims.
#[derive(Debug, Parser)]
pub struct InsuranceListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsuranceListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Claims");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listInsuranceClaims", serde_json::Value::Null)
            .await?;

        let claims = result
            .get("claims")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

        println!();
        output::print_field("Total Claims", &count.to_string());
        println!();

        if claims.is_empty() {
            output::print_warning("The pool has paid no claims.");
            return Ok(());
        }

        for (i, claim) in claims.iter().enumerate() {
            println!("Claim #{}", i + 1);
            for (key, val) in claim.as_object().unwrap_or(&serde_json::Map::new()) {
                output::print_field(key, val.to_string().trim_matches('"'));
            }
            println!();
        }

        Ok(())
    }
}

/// Inspect a single insurance claim by id.
#[derive(Debug, Parser)]
pub struct InsuranceGetCmd {
    /// Claim ID (hex)
    claim_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsuranceGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Claim Details");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getInsuranceClaim",
                serde_json::json!({ "claim_id": self.claim_id }),
            )
            .await?;

        if result.is_null() {
            output::print_warning(&format!("No paid claim with id {}", self.claim_id));
            return Ok(());
        }

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

/// Show insurance pool aggregate state.
#[derive(Debug, Parser)]
pub struct InsurancePoolCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InsurancePoolCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Insurance Pool");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getInsurancePoolBalance", serde_json::Value::Null)
            .await?;

        println!();
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_names_exactly_one_piece_of_evidence() {
        let cmd = || InsuranceClaimCmd {
            recon_adapter: None,
            recon_chain: None,
            recon_position: None,
            key_namespace: "client".into(),
            rpc: String::new(),
        };
        let mut recon = cmd();
        recon.recon_adapter = Some("ccip".into());
        recon.recon_chain = Some("Ethereum".into());
        recon.recon_position = Some(3);
        assert!(matches!(
            recon.evidence().unwrap(),
            InsuranceEvidence::ReconMismatch { ref chain, position: 3, .. } if chain == "ethereum"
        ));
        recon.recon_adapter = Some("nope".into());
        assert!(recon.evidence().is_err());
        assert!(cmd().evidence().is_err());
    }
}
