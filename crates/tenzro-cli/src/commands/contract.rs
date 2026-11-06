//! Contract deployment commands for the Tenzro CLI
//!
//! Deploy and manage smart contracts across the EVM and SVM.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Contract management commands
#[derive(Debug, Subcommand)]
pub enum ContractCommand {
    /// Deploy an EVM contract from the signing account
    Deploy(ContractDeployCmd),
    /// Call contracts in the EVM and the SVM as one all-or-nothing
    /// transaction
    Call(ContractCallCmd),
}

impl ContractCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deploy(cmd) => cmd.execute().await,
            Self::Call(cmd) => cmd.execute().await,
        }
    }
}

/// Deploy an EVM contract: one transaction the signing account sends, which
/// creates the contract at the address the account and its nonce give.
#[derive(Debug, Parser)]
pub struct ContractDeployCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Contract creation code (hex-encoded, with optional 0x prefix)
    #[arg(long)]
    bytecode: String,
    /// Constructor arguments (hex-encoded ABI)
    #[arg(long)]
    args: Option<String>,
    /// Gas limit
    #[arg(long, default_value = "3000000")]
    gas_limit: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ContractDeployCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let code = hex::decode(self.bytecode.trim_start_matches("0x"))?;
        let args = match &self.args {
            Some(a) => hex::decode(a.trim_start_matches("0x"))?,
            None => Vec::new(),
        };
        output::print_header("Deploy Contract");
        let spinner = output::create_spinner("Sending the deployment...");
        let rpc = RpcClient::new(&self.rpc);
        let account =
            crate::keystore::address32(&crate::keystore::client_account(&self.key_namespace)?.0)?;
        let result: serde_json::Value = crate::keystore::send_deployment(
            &rpc,
            &self.key_namespace,
            account,
            serde_json::json!({ "ContractDeploy": { "code": code, "args": args } }),
            self.gas_limit,
        )
        .await?;
        spinner.finish_and_clear();

        output::print_success("Transaction submitted");
        output::print_field(
            "Transaction",
            result
                .as_str()
                .or_else(|| result.get("tx_hash").and_then(|v| v.as_str()))
                .unwrap_or("unknown"),
        );
        output::print_field("Deployer", &format!("0x{}", hex::encode(account)));
        Ok(())
    }
}

/// Send one contract-call transaction: the calls run in order, each in its
/// VM, and either all take effect or none does.
#[derive(Debug, Parser)]
pub struct ContractCallCmd {
    /// Hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// A call, `<vm>:<to hex>:<calldata hex>[:<value wei>]` with vm one of
    /// evm or svm. Repeat for each call, in order.
    #[arg(long = "call", required = true)]
    calls: Vec<String>,
    /// Gas for all the calls together
    #[arg(long, default_value = "1000000")]
    gas_limit: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// Parse `<vm>:<to hex>:<calldata hex>[:<value wei>]`.
fn parse_call(spec: &str) -> Result<tenzro_types::VmCall> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 && parts.len() != 4 {
        anyhow::bail!("a call is <vm>:<to hex>:<calldata hex>[:<value wei>], got {spec}");
    }
    let vm = match parts[0].to_ascii_lowercase().as_str() {
        "evm" => tenzro_types::CallVm::Evm,
        "svm" => tenzro_types::CallVm::Svm,
        other => anyhow::bail!("unknown VM {other}: evm or svm"),
    };
    let to = hex::decode(parts[1].trim_start_matches("0x"))?;
    let data = hex::decode(parts[2].trim_start_matches("0x"))?;
    let value = match parts.get(3) {
        Some(v) => v.parse::<u128>()?,
        None => 0,
    };
    Ok(tenzro_types::VmCall {
        vm,
        to,
        value,
        data,
    })
}

impl ContractCallCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let calls = self
            .calls
            .iter()
            .map(|c| parse_call(c))
            .collect::<Result<Vec<_>>>()?;
        tenzro_types::VmCall::validate_list(&calls).map_err(|e| anyhow::anyhow!(e))?;

        output::print_header("Contract Call");
        let spinner = output::create_spinner(&format!("Sending {} call(s)...", calls.len()));
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            crate::keystore::address32(&crate::keystore::client_account(&self.key_namespace)?.0)?,
            serde_json::json!({ "ContractCall": { "calls": calls } }),
            self.gas_limit,
        )
        .await?;
        spinner.finish_and_clear();

        output::print_success("Transaction submitted");
        output::print_field(
            "Transaction",
            result
                .as_str()
                .or_else(|| result.get("tx_hash").and_then(|v| v.as_str()))
                .unwrap_or("unknown"),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_spec_names_its_vm_target_data_and_value() {
        let c = parse_call("svm:0x0606:0x0102").unwrap();
        assert_eq!(c.vm, tenzro_types::CallVm::Svm);
        assert_eq!(c.to, vec![6, 6]);
        assert_eq!(c.data, vec![1, 2]);
        assert_eq!(c.value, 0);
        assert_eq!(parse_call("evm:aa:bb:7").unwrap().value, 7);
        assert!(parse_call("move:aa:bb").is_err());
        assert!(parse_call("evm:aa").is_err());
    }
}
