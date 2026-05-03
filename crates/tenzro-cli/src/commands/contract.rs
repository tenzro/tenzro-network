//! Contract deployment commands for the Tenzro CLI
//!
//! Deploy and manage smart contracts across EVM, SVM, and DAML VMs.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Contract management commands
#[derive(Debug, Subcommand)]
pub enum ContractCommand {
    /// Deploy a smart contract to EVM, SVM, or DAML
    Deploy(ContractDeployCmd),
    /// Encode a function call (ABI encoding)
    Encode(ContractEncodeCmd),
    /// Decode a function result (ABI decoding)
    Decode(ContractDecodeCmd),
}

impl ContractCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deploy(cmd) => cmd.execute().await,
            Self::Encode(cmd) => cmd.execute().await,
            Self::Decode(cmd) => cmd.execute().await,
        }
    }
}

/// Deploy a smart contract
#[derive(Debug, Parser)]
pub struct ContractDeployCmd {
    /// Target VM: evm, svm, or daml
    #[arg(long)]
    vm: String,
    /// Contract bytecode (hex-encoded, with optional 0x prefix)
    #[arg(long)]
    bytecode: String,
    /// Deployer address (hex)
    #[arg(long)]
    deployer: String,
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

        output::print_header("Deploy Contract");
        let spinner = output::create_spinner(&format!("Deploying to {}...", self.vm));
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "vm_type": self.vm,
            "bytecode": self.bytecode,
            "deployer": self.deployer,
            "gas_limit": self.gas_limit,
        });

        if let Some(ref args) = self.args {
            params["constructor_args"] = serde_json::json!(args);
        }

        let result: serde_json::Value = rpc.call("tenzro_deployContract", params).await?;

        spinner.finish_and_clear();

        output::print_success("Contract deployed successfully!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Gas Used", &result.get("gas_used").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("VM", result.get("vm_type").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Encode a function call
#[derive(Debug, Parser)]
pub struct ContractEncodeCmd {
    /// Function signature (e.g. "transfer(address,uint256)")
    #[arg(long)]
    function: String,
    /// Arguments as JSON array (e.g. '["0xabc...", "1000"]')
    #[arg(long)]
    args: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ContractEncodeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Encode Function Call");
        let rpc = RpcClient::new(&self.rpc);
        let args: serde_json::Value = serde_json::from_str(&self.args)?;
        let result: serde_json::Value = rpc.call("tenzro_encodeFunction", serde_json::json!({
            "function": self.function,
            "args": args,
        })).await?;
        output::print_field("Function", &self.function);
        output::print_field("Encoded", result.get("encoded").and_then(|v| v.as_str()).unwrap_or(""));
        Ok(())
    }
}

/// Decode a function result
#[derive(Debug, Parser)]
pub struct ContractDecodeCmd {
    /// Function signature to decode against
    #[arg(long)]
    function: String,
    /// Hex-encoded return data
    #[arg(long)]
    data: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ContractDecodeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Decode Function Result");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_decodeResult", serde_json::json!({
            "function": self.function,
            "data": self.data,
        })).await?;
        output::print_field("Function", &self.function);
        if let Some(values) = result.get("values").and_then(|v| v.as_array()) {
            for (i, val) in values.iter().enumerate() {
                output::print_field(&format!("Value {}", i), val.to_string().trim_matches('"'));
            }
        } else {
            output::print_json(&result)?;
        }
        Ok(())
    }
}
