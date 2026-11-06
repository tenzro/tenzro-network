//! Bridge SDK for Tenzro Network
//!
//! TNZO moves between Tenzro and external chains only over governed routes:
//! a CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana, IBC,
//! Bitcoin deposits and contract routes. Every route enforces the same rules: committee
//! attestations bound to the chain, the route, a nonce and an expiry; a
//! circuit breaker; per-transfer and per-epoch caps; and the supply
//! invariant (what is outstanding on the external chain never exceeds the
//! TNZO locked on Tenzro for that route).
//!
//! - [`BridgeClient::list_routes`] / [`BridgeClient::get_route`] read the
//!   governed routes with their caps, usage and supply.
//! - [`BridgeClient::send`] moves TNZO, or a carried asset such as USDC, out:
//!   a `Bridge` transaction the holder's signer signs locally.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
use crate::wallet::HybridSigner;
use std::sync::Arc;

/// The `Bridge` transaction fields that send `amount` base units to
/// `recipient` (hex, the account on `target_chain`). `asset` names a carried
/// asset (`USDC`), whose representation is burned here and released from the
/// route's vault there; `None` moves TNZO, or the deposit asset over a deposit
/// route.
pub fn outbound_fields(
    target_chain: &str,
    recipient: &str,
    amount: u128,
    asset: Option<&str>,
) -> SdkResult<serde_json::Value> {
    let recipient = recipient.trim_start_matches("0x");
    if recipient.is_empty() || hex::decode(recipient).is_err() {
        return Err(SdkError::InvalidParameter(
            "recipient must be non-empty hex".into(),
        ));
    }
    if amount == 0 {
        return Err(SdkError::InvalidParameter("amount must be positive".into()));
    }
    Ok(serde_json::json!({ "op": { "outbound": {
        "target_chain": target_chain.to_ascii_lowercase(),
        "recipient": recipient.to_ascii_lowercase(),
        "amount": amount.to_string(),
        "asset": asset.map(str::to_ascii_uppercase),
    }}}))
}

/// Bridge client
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let routes = client.bridge().list_routes().await?;
/// for route in &routes {
///     println!("{} mode={}", route["key"], route["mode"]);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct BridgeClient {
    rpc: Arc<RpcClient>,
}

impl BridgeClient {
    /// Creates a new bridge client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Every governed route, as `tenzro_listBridgeRoutes` publishes it.
    pub async fn list_routes(&self) -> SdkResult<Vec<serde_json::Value>> {
        let result: serde_json::Value = self
            .rpc
            .call("tenzro_listBridgeRoutes", serde_json::json!({}))
            .await?;
        Ok(result["routes"].as_array().cloned().unwrap_or_default())
    }

    /// The route for `adapter` (`ccip`, `ibc`, `deposit` or `contract`) and `chain`.
    pub async fn get_route(&self, adapter: &str, chain: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getBridgeRoute",
                serde_json::json!({ "adapter": adapter, "source_chain": chain }),
            )
            .await
    }

    /// Outbound record `sequence` of the route `(adapter, chain)`, as
    /// relayers and signers take it; for a Bitcoin deposit route, the
    /// withdrawal and the digest each input is signed over.
    pub async fn get_outbound(
        &self,
        adapter: &str,
        chain: &str,
        sequence: u64,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getBridgeOutbound",
                serde_json::json!({ "adapter": adapter, "source_chain": chain, "sequence": sequence }),
            )
            .await
    }

    /// The network-wide exit limits: for each unit, the cap in force per
    /// epoch (the lower of its governed cap and the stake-backed cap), the
    /// governed cap, how much has left over every route together this epoch
    /// and how much waits in the exit queue; the security ratio and its
    /// inputs (`security`); the exit delay rule; the most one proposal may
    /// raise a cap; and the last exit id queued.
    pub async fn get_outflow(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getBridgeOutflow", serde_json::json!({}))
            .await
    }

    /// The queued exit `id`: its sender, destination, amount and release
    /// time.
    pub async fn get_exit(&self, id: u64) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getBridgeExit", serde_json::json!({ "id": id }))
            .await
    }

    /// Send `amount` base units out over the route to `target_chain`, to
    /// `recipient` (hex), as a `Bridge` transaction `signer` signs locally.
    /// `asset` names a carried asset (`USDC`); `None` moves TNZO.
    pub async fn send(
        &self,
        signer: &dyn HybridSigner,
        target_chain: &str,
        recipient: &str,
        amount: u128,
        asset: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        let tx = TypedTransaction::new(
            TxKind::Bridge,
            outbound_fields(target_chain, recipient, amount, asset)?,
        )?;
        TypedTxClient::new(self.rpc.clone()).send(signer, &tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_fields_match_the_shared_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/payment-ops/vectors.json");
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for v in vectors["bridge_outbound"].as_array().unwrap() {
            let a = &v["args"];
            let fields = outbound_fields(
                a["target_chain"].as_str().unwrap(),
                a["recipient"].as_str().unwrap(),
                a["amount"].as_str().unwrap().parse().unwrap(),
                a["asset"].as_str(),
            )
            .unwrap();
            assert_eq!(fields, v["fields"]);
        }
        assert!(outbound_fields("base", "zz", 1, None).is_err());
        assert!(outbound_fields("base", "01", 0, None).is_err());
    }
}
