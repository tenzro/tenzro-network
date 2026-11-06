//! Contract SDK for Tenzro Network
//!
//! This module provides smart contract deployment functionality across
//! the multi-VM runtime (EVM, SVM).

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
use crate::wallet::HybridSigner;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Contract client: deploy EVM contracts and read them.
///
/// A deployment is a `ContractDeploy` transaction the deployer signs on its
/// own hardware; the signature covers the code, the arguments, the nonce,
/// the chain and the sender. The contract is created when a block executes
/// the transaction, at the address its receipt reports.
#[derive(Clone)]
pub struct ContractClient {
    rpc: Arc<RpcClient>,
}

impl ContractClient {
    /// Creates a new contract client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Sign a `ContractDeploy` of `code` with `constructor_args` appended,
    /// as `signer`, and submit it through `tenzro_deployContract`.
    /// `gas_limit` defaults to 3,000,000.
    pub async fn deploy(
        &self,
        signer: &dyn HybridSigner,
        code: &[u8],
        constructor_args: &[u8],
        gas_limit: Option<u64>,
    ) -> SdkResult<DeployResult> {
        let tx = TypedTransaction::new(
            TxKind::ContractDeploy,
            serde_json::json!({ "code": code, "args": constructor_args }),
        )?
        .gas_limit(gas_limit.unwrap_or(3_000_000));
        let answer = TypedTxClient::new(self.rpc.clone())
            .send_via("tenzro_deployContract", signer, &tx)
            .await?;
        serde_json::from_value(answer)
            .map_err(|e| crate::error::SdkError::RpcError(format!("tenzro_deployContract: {e}")))
    }

    /// Performs a read-only contract call (eth_call)
    ///
    /// Executes a contract call without creating a transaction on-chain.
    /// Useful for reading state from smart contracts.
    ///
    /// # Arguments
    ///
    /// * `to` - Contract address (hex)
    /// * `data` - ABI-encoded call data (hex)
    /// * `block` - Optional block number or "latest" (default: "latest")
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let contract = client.contract();
    /// let result = contract.call_contract(
    ///     "0x1234...",
    ///     "0x70a08231000000000000000000000000abcdef...",
    ///     None,
    /// ).await?;
    /// println!("Return data: {}", result.data);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn call_contract(
        &self,
        to: &str,
        data: &str,
        block: Option<&str>,
    ) -> SdkResult<CallResult> {
        let block_param = block.unwrap_or("latest");
        let result: String = self
            .rpc
            .call(
                "eth_call",
                serde_json::json!([{ "to": to, "data": data }, block_param]),
            )
            .await?;
        Ok(CallResult { data: result })
    }
}

/// Result from a read-only contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    /// Hex-encoded return data
    pub data: String,
}

/// The VM a [`VmCall`] executes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallVm {
    /// The EVM.
    Evm,
    /// The SVM.
    Svm,
}

/// One call of a contract-call transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmCall {
    /// The VM the call executes in.
    pub vm: CallVm,
    /// The code called: an EVM contract (20 bytes) or an SVM program
    /// (32 bytes).
    pub to: Vec<u8>,
    /// Native TNZO the call carries, wei. Only EVM calls carry value.
    pub value: u128,
    /// Calldata in the VM's own format.
    pub data: Vec<u8>,
}

/// Result from a contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    /// Hash of the `ContractDeploy` transaction.
    pub tx_hash: String,
    /// `"admitted"`: the transaction is in the mempool.
    pub status: String,
}
