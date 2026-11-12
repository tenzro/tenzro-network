//! The node as an ACP seller of paid AI work.
//!
//! A line item's `item.id` is `<model>/<unit>` (for example
//! `my-model/output_tokens`) and its `quantity` the number of units; the
//! price is this node's rate card for that model, and work the card leaves
//! unpriced is not for sale. A session is paid by an x402 `tenzro-hybrid`
//! payment to this node's recipient whose challenge id is the session id,
//! settled through the node's own x402 facilitator, which binds the payer's
//! DID, holds the payment to the payer's Terms and checks any AP2 mandates
//! the payment carries. The ledger refuses a second settlement of the same
//! challenge id, so a session is paid at most once.

use std::sync::Arc;

use async_trait::async_trait;
use tenzro_payments::acp::{SESSION_TTL_SECS, Seller};
use tenzro_payments::x402::{X402PaymentPayload, X402PaymentRequirement, X402SettlementResponse};
use tenzro_types::model::BillableUnits;

use crate::node::TenzroNode;

/// The hardware key this node authorizes its UCP checkouts with, under the
/// label [`NodeMerchant::LABEL`].
pub struct NodeMerchant {
    key: Box<dyn tenzro_device_key::HardwareSigner>,
    public: p256::ecdsa::VerifyingKey,
}

impl NodeMerchant {
    /// The label of the business key.
    pub const LABEL: &'static str = "ucp/merchant";

    /// Open this machine's business key, creating it in the hardware the
    /// first time.
    pub fn open() -> Result<Self, String> {
        let key = tenzro_device_key::signer::open_or_create(Self::LABEL)
            .map_err(|e| format!("business key: {e}"))?;
        let sec1 = key
            .public_key_sec1()
            .map_err(|e| format!("business key: {e}"))?;
        let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|e| format!("business key: {e}"))?;
        Ok(Self { key, public })
    }
}

impl tenzro_payments::ucp::MerchantKey for NodeMerchant {
    fn public_key(&self) -> p256::ecdsa::VerifyingKey {
        self.public
    }
    fn sign(&self, signing_input: &[u8]) -> Result<p256::ecdsa::Signature, String> {
        let raw = self
            .key
            .sign(signing_input)
            .map_err(|e| format!("business key: {e}"))?;
        p256::ecdsa::Signature::from_slice(&raw).map_err(|e| e.to_string())
    }
}

/// Sells this node's served models over ACP.
pub struct NodeSeller {
    node: Arc<TenzroNode>,
}

impl NodeSeller {
    /// A seller for `node`.
    pub fn new(node: Arc<TenzroNode>) -> Self {
        Self { node }
    }
}

#[async_trait]
impl Seller for NodeSeller {
    fn price(&self, item_id: &str, quantity: u64) -> Result<(u128, String), String> {
        let (model, unit) = item_id.rsplit_once('/').ok_or_else(|| {
            "item.id is <model>/<unit>, for example <model>/output_tokens".to_string()
        })?;
        let (served, _) = crate::visibility_rpc::announced_models(
            &self.node.served_models,
            self.node.visibility(),
        );
        if !served.iter().any(|m| m == model) {
            return Err(format!("this node does not serve {model}"));
        }
        let mut units = BillableUnits::new();
        units
            .set(unit, u128::from(quantity))
            .map_err(|e| e.to_string())?;
        let card = self.node.provider_pricing.read().card_for(model).clone();
        let wei = crate::inference_pricing::charge_wei(&self.node, &card, &units)
            .map_err(|e| e.to_string())?;
        if wei == 0 {
            return Err(format!("the rate card for {model} does not price {unit}"));
        }
        Ok((wei, "TNZO".to_string()))
    }

    fn requirement(&self, session_id: &str, total: u128, asset: &str) -> X402PaymentRequirement {
        let mut r = X402PaymentRequirement::new(
            tenzro_payments::x402::DEFAULT_SCHEME,
            format!("tenzro:{}", self.node.config().chain_id()),
            total.to_string(),
            self.node.config().payments.recipient.clone(),
            asset,
            SESSION_TTL_SECS as u64,
        );
        r.set_extra(
            tenzro_payments::x402::CHALLENGE_ID_KEY,
            serde_json::json!(session_id),
        );
        r
    }

    async fn settle(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse {
        match self.node.x402_facilitator_service() {
            Some(f) => f.settle(requirement, payload).await,
            None => X402SettlementResponse::failed(
                requirement.network.clone(),
                "this node settles no payments yet",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seller() -> (NodeSeller, tempfile::TempDir) {
        let (node, tmp) = crate::bare_node().await;
        (NodeSeller::new(node), tmp)
    }

    #[tokio::test]
    async fn an_item_id_must_name_a_model_and_a_unit() {
        let (seller, _tmp) = seller().await;
        for id in ["", "output_tokens", "model-without-unit"] {
            let e = seller.price(id, 10).unwrap_err();
            assert!(e.contains("<model>/<unit>"), "{id}: {e}");
        }
    }

    #[tokio::test]
    async fn a_model_this_node_does_not_serve_is_not_for_sale() {
        let (seller, _tmp) = seller().await;
        let e = seller.price("some-model/output_tokens", 10).unwrap_err();
        assert_eq!(e, "this node does not serve some-model");
        let e = seller.price("org/some-model/output_tokens", 1).unwrap_err();
        assert_eq!(
            e, "this node does not serve org/some-model",
            "the unit is the last segment"
        );
    }

    #[tokio::test]
    async fn the_requirement_binds_the_session_the_total_and_this_nodes_recipient() {
        let (seller, _tmp) = seller().await;
        let r = seller.requirement("session-7", 1234, "TNZO");
        assert_eq!(r.scheme, tenzro_payments::x402::DEFAULT_SCHEME);
        assert_eq!(
            r.network,
            format!("tenzro:{}", seller.node.config().chain_id())
        );
        assert_eq!(r.amount, "1234");
        assert_eq!(r.asset, "TNZO");
        assert_eq!(r.pay_to, seller.node.config().payments.recipient);
        assert_eq!(r.max_timeout_seconds, SESSION_TTL_SECS as u64);
        assert_eq!(
            r.extra_str(tenzro_payments::x402::CHALLENGE_ID_KEY),
            Some("session-7"),
            "the challenge id is the session id, so a session is paid at most once"
        );
    }

    #[tokio::test]
    async fn a_node_without_a_facilitator_settles_nothing() {
        let (seller, _tmp) = seller().await;
        let requirement = seller.requirement("session-8", 5, "TNZO");
        let payload = X402PaymentPayload::new(requirement.clone(), serde_json::json!({}));
        let out = seller.settle(&requirement, &payload).await;
        assert!(!out.success);
        assert_eq!(out.network, requirement.network);
        assert_eq!(
            out.error_reason.as_deref(),
            Some("this node settles no payments yet")
        );
        assert!(out.transaction.is_empty());
    }
}
