//! Paid carriage: when the access policy's rule for the `iroh` surface's
//! `read` class is `paid`, a device pays the rule's price for each mebibyte
//! carried for it, both directions together. It signs a ceiling under the
//! node's x402 `upto` challenge before anything is carried, and the node
//! charges what it carried beneath that ceiling when the session ends, with
//! a usage record its meter signed.

use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use tenzro_payments::gateway::PaymentExpectation;
use tenzro_payments::metering::UsageLine;
use tenzro_payments::traits::PaymentGateway as _;
use tenzro_payments::types::PaymentCredential;

use super::{Hold, Payments};
use crate::node::TenzroNode;

/// The resource a carriage payment is minted for and settled against.
pub const RESOURCE: &str = "/app-transport";

/// The unit a carriage charge is metered in.
pub const MEBIBYTES: &str = "mebibytes";

const MEBIBYTE: u128 = 1 << 20;

/// Takes carriage payments through the node's payment gateway.
pub struct NodePayments {
    node: Arc<OnceLock<Weak<TenzroNode>>>,
    mebibytes: Option<u64>,
}

impl NodePayments {
    /// Payments to the node `node` comes to hold, each session paying up front
    /// for at most `mebibytes`.
    pub fn new(node: Arc<OnceLock<Weak<TenzroNode>>>, mebibytes: Option<u64>) -> Self {
        Self { node, mebibytes }
    }

    fn node(&self) -> Result<Arc<TenzroNode>, String> {
        self.node
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| "this node is not serving".to_string())
    }
}

/// The policy's price of a mebibyte, when it is a whole amount in the asset
/// this node is paid in.
fn per_mebibyte(node: &TenzroNode, price: &str, asset: &str) -> Result<u128, String> {
    let taken = &node.config().payments.default_asset;
    if asset != taken {
        return Err(format!(
            "the access policy prices carriage in {asset}, and this node is paid in {taken}"
        ));
    }
    match price.parse::<u128>() {
        Ok(price) if price > 0 => Ok(price),
        _ => Err(format!(
            "the access policy's price {price} is not a whole amount"
        )),
    }
}

#[async_trait]
impl Payments for NodePayments {
    async fn quote(&self, price: &str, asset: &str) -> Result<String, String> {
        let node = self.node()?;
        let price = per_mebibyte(&node, price, asset)?;
        let mebibytes = self.mebibytes.ok_or_else(|| {
            "this node takes no payment for carriage (app_transport.paid_mebibytes is unset)"
                .to_string()
        })?;
        let ceiling = price
            .checked_mul(u128::from(mebibytes))
            .ok_or_else(|| "the paid budget overflows".to_string())?;
        let challenge = crate::payment_gate::mint_for_resource(&node, RESOURCE, ceiling)
            .await
            .map_err(|e| format!("this node cannot take payment now: {e}"))?;
        serde_json::to_string(&challenge).map_err(|e| e.to_string())
    }

    async fn hold(&self, credential: &str, price: &str, asset: &str) -> Result<Hold, String> {
        let node = self.node()?;
        let price = per_mebibyte(&node, price, asset)?;
        let parsed: PaymentCredential =
            serde_json::from_str(credential).map_err(|e| format!("payment credential: {e}"))?;
        let gateway = node
            .payment_gateway()
            .ok_or_else(|| "this node takes no payment now".to_string())?;
        let payments = &node.config().payments;
        gateway
            .verify_metered(
                &parsed,
                PaymentExpectation::Resource {
                    resource: RESOURCE,
                    payee: &payments.recipient,
                    min_amount: price,
                    asset: &payments.default_asset,
                },
            )
            .await
            .map_err(|e| format!("payment refused: {e}"))?;
        let ceiling = tenzro_payments::payer_auth::authorized_ceiling(&parsed)
            .map_err(|e| format!("payment refused: {e}"))?;
        let bytes = (ceiling / price).saturating_mul(MEBIBYTE);
        Ok(Hold {
            credential: credential.to_string(),
            price,
            bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
        })
    }

    async fn settle(&self, hold: Hold, mebibytes: u64) {
        if mebibytes == 0 {
            return;
        }
        let Ok(node) = self.node() else {
            return;
        };
        let Ok(credential) = serde_json::from_str::<PaymentCredential>(&hold.credential) else {
            return;
        };
        let charge = u128::from(mebibytes) * hold.price;
        let lines = vec![UsageLine {
            unit: MEBIBYTES.to_string(),
            quantity: u128::from(mebibytes),
            unit_price: hold.price,
        }];
        match crate::payment_gate::settle_metered(&node, &credential, RESOURCE, lines, charge).await
        {
            Ok(receipt) => tracing::info!(
                payer = %credential.payer_did,
                mebibytes,
                charge,
                receipt = %receipt.receipt_id,
                "app transport carriage settled"
            ),
            Err(e) => tracing::warn!(
                payer = %credential.payer_did,
                mebibytes,
                charge,
                error = %e,
                "app transport carriage could not be settled"
            ),
        }
    }
}
