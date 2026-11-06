//! Binding the node's priced surfaces to what they sell.
//!
//! Every priced surface (static sites, functions, machines, Open databases and
//! files) mints its challenges and verifies its credentials through the two
//! helpers here, so a credential is only ever accepted for the resource it was
//! minted for, paid to this node's operator, at the resource's price, in the
//! operator's asset. A credential for any other challenge, including a cheap
//! one the caller minted to themselves, is refused before anything settles.

use std::sync::Arc;

use tenzro_payments::gateway::PaymentExpectation;
use tenzro_payments::traits::PaymentGateway as _;
use tenzro_payments::types::{PaymentChallenge, PaymentCredential, PaymentReceipt};
use tenzro_payments::{PaymentError, Result as PaymentResult};

use crate::node::TenzroNode;

/// The canonical resource string of a static-site path.
pub fn site_resource(site_id: &str, path: &str) -> String {
    format!("/sites/{site_id}{path}")
}

/// The canonical resource string of a function deployment.
pub fn function_resource(function_id: &str) -> String {
    format!("/functions/{function_id}")
}

/// The canonical resource string of a machine deployment.
pub fn machine_resource(machine_id: &str) -> String {
    format!("/machines/{machine_id}")
}

fn gateway(
    node: &Arc<TenzroNode>,
) -> PaymentResult<&Arc<tenzro_payments::gateway::TenzroPaymentGateway>> {
    node.payment_gateway()
        .ok_or_else(|| PaymentError::ConfigError("payment gateway unavailable".to_string()))
}

/// Mint the challenge a caller pays to reach `resource` at `price`.
pub async fn mint_for_resource(
    node: &Arc<TenzroNode>,
    resource: &str,
    price: u128,
) -> PaymentResult<PaymentChallenge> {
    let payments = &node.config().payments;
    gateway(node)?
        .create_challenge(
            &payments.default_protocol,
            resource,
            price,
            &payments.default_asset,
            &payments.recipient,
        )
        .await
}

/// The unit a fixed-price surface meters: one request at its price.
pub const REQUEST_UNIT: &str = "requests";

/// Verify and settle `credential` as payment for one request to `resource`.
///
/// When the credential answers a metered challenge (one naming this node's
/// meter key), the node signs a usage record for what it serves, one request
/// at `price`, and charges exactly that beneath the payer's ceiling. The
/// record rides back to the buyer in the receipt, and so in
/// `PAYMENT-RESPONSE`, as the evidence it disputes the charge with.
pub async fn settle_for_resource(
    node: &Arc<TenzroNode>,
    credential: &PaymentCredential,
    resource: &str,
    price: u128,
) -> PaymentResult<PaymentReceipt> {
    let lines = vec![tenzro_payments::metering::UsageLine {
        unit: REQUEST_UNIT.to_string(),
        quantity: 1,
        unit_price: price,
    }];
    let metered = meter(node, credential, lines)?;
    let credential = metered.as_ref().map(|(c, _)| c).unwrap_or(credential);
    let payments = &node.config().payments;
    let mut receipt = gateway(node)?
        .verify_and_settle(
            credential,
            PaymentExpectation::Resource {
                resource,
                payee: &payments.recipient,
                min_amount: price,
                asset: &payments.default_asset,
            },
        )
        .await?;
    if let Some((_, record)) = metered {
        receipt.extra.insert(
            tenzro_payments::metering::USAGE_RECORD_KEY.to_string(),
            serde_json::to_value(&record)
                .map_err(|e| PaymentError::SerializationError(e.to_string()))?,
        );
    }
    Ok(receipt)
}

/// Meter `credential` for `lines` when it answers a challenge that names this
/// node's meter: returns the charged credential and the signed record, or
/// `None` for an unmetered challenge, which settles as presented.
pub fn meter(
    node: &Arc<TenzroNode>,
    credential: &PaymentCredential,
    lines: Vec<tenzro_payments::metering::UsageLine>,
) -> PaymentResult<Option<(PaymentCredential, tenzro_payments::metering::UsageRecord)>> {
    let Some(x402) = node.x402_server() else {
        return Ok(None);
    };
    let Ok(challenge) = x402.challenge_store().get(&credential.challenge_id) else {
        // The gateway refuses an unknown challenge on its own.
        return Ok(None);
    };
    if !challenge
        .extra
        .contains_key(tenzro_payments::metering::METER_KEY)
    {
        return Ok(None);
    }
    let mut charged = credential.clone();
    let record = x402.meter(&challenge, &mut charged, lines)?;
    Ok(Some((charged, record)))
}

/// Settle `upto` payments through `gate` at the metered cost of the work
/// (when `on`), with this node's x402 meter signing the usage record each
/// metered charge carries.
pub fn with_metering(
    node: &TenzroNode,
    gate: tenzro_payments::middleware::PaymentGateMiddleware,
    on: bool,
) -> tenzro_payments::middleware::PaymentGateMiddleware {
    let gate = gate.with_metered_settlement(on);
    match node.x402_server() {
        Some(x402) => gate.with_meter(x402.clone()),
        None => gate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_are_named_by_surface_and_id() {
        assert_eq!(site_resource("s1", "/a/b"), "/sites/s1/a/b");
        assert_eq!(function_resource("f1"), "/functions/f1");
        assert_eq!(machine_resource("m1"), "/machines/m1");
        assert_ne!(site_resource("s1", "/x"), site_resource("s2", "/x"));
    }

    #[tokio::test]
    async fn a_node_without_a_payment_gateway_mints_no_challenge() {
        let (node, _tmp) = crate::bare_node().await;
        let err = mint_for_resource(&node, "/functions/f1", 5).await.unwrap_err();
        assert!(
            matches!(err, PaymentError::ConfigError(ref m) if m.contains("gateway unavailable")),
            "{err}"
        );
    }

    fn credential(challenge_id: &str) -> PaymentCredential {
        PaymentCredential {
            credential_id: "c1".to_string(),
            challenge_id: challenge_id.to_string(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:human:p".to_string(),
            payer_address: String::new(),
            amount: 5,
            asset: "TNZO".to_string(),
            signature: None,
            extra: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_node_without_a_payment_gateway_settles_no_credential() {
        let (node, _tmp) = crate::bare_node().await;
        let credential = credential("unknown");
        let err = settle_for_resource(&node, &credential, "/functions/f1", 5)
            .await
            .unwrap_err();
        assert!(matches!(err, PaymentError::ConfigError(_)), "{err}");
    }

    #[tokio::test]
    async fn a_credential_for_an_unknown_challenge_is_not_metered() {
        let (node, _tmp) = crate::bare_node().await;
        let credential = credential("no-such-challenge");
        let metered = meter(&node, &credential, Vec::new()).unwrap();
        assert!(metered.is_none(), "the gateway refuses it on its own");
    }
}
