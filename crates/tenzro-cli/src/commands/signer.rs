//! Who signs a native transaction from the CLI, and where it goes: the
//! client account's hardware key, by namespace, and an RPC endpoint.

use anyhow::{Result, anyhow};
use clap::Args;
use tenzro_types::transaction::TransactionType;

use crate::output;
use crate::rpc::RpcClient;

/// Gas a native transaction is sent with unless its command names more.
pub(crate) const DEFAULT_TX_GAS: u64 = 400_000;

/// Who signs, and where the transaction goes.
#[derive(Debug, Args)]
pub(crate) struct Signer {
    /// The signing account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Signer {
    /// The RPC endpoint.
    pub(crate) fn rpc_url(&self) -> &str {
        &self.rpc
    }

    /// The signing account's hardware key namespace.
    pub(crate) fn key_namespace(&self) -> &str {
        &self.key_namespace
    }

    /// Sign `tx` as the client account and submit it.
    pub(crate) async fn send_tx(&self, tx: TransactionType, what: &str) -> Result<()> {
        self.send_tx_with_gas(tx, what, DEFAULT_TX_GAS).await
    }

    /// Sign `tx` as the client account, which pays its gas up to
    /// `gas_limit`, and submit it.
    pub(crate) async fn send_tx_with_gas(
        &self,
        tx: TransactionType,
        what: &str,
        gas_limit: u64,
    ) -> Result<()> {
        self.send_tx_at(tx, what, gas_limit).await.map(|_| ())
    }

    /// [`Self::send_tx_with_gas`], returning the signing account and the
    /// nonce the transaction took.
    pub(crate) async fn send_tx_at(
        &self,
        tx: TransactionType,
        what: &str,
        gas_limit: u64,
    ) -> Result<([u8; 32], u64)> {
        let rpc = RpcClient::new(&self.rpc);
        let tx_type = serde_json::to_value(tx)?;
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        let to: [u8; 32] = hex::decode(account.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| anyhow!("the client account is not 32 bytes"))?;
        let (result, nonce) = crate::keystore::send_as_client_with_nonce(
            &rpc,
            &self.key_namespace,
            to,
            tx_type,
            gas_limit,
        )
        .await?;
        output::print_success(&format!("{what} signed in hardware and submitted"));
        output::print_field("Signer", &account);
        output::print_field(
            "Tx Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok((to, nonce))
    }
}
