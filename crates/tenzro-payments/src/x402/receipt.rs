//! x402 settlement responses: the body of the `PAYMENT-RESPONSE` header.
//!
//! A paid response carries `PAYMENT-RESPONSE: <base64 JSON>` naming the
//! transaction that moved the funds. For a payment settled on the Tenzro
//! Ledger that is the hash of a transaction the node saw executed
//! successfully before it served the response, so a buyer checks the claim
//! with `tenzro_getTransactionReceipt` against any node. For an
//! escrow-voucher payment it is the escrow the accepted voucher draws on; the
//! funds move when the payee claims the voucher on-chain.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::types::PaymentReceipt;
use crate::x402::payment_required::{decode_header, encode_header};

/// The body of `PAYMENT-RESPONSE`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct X402SettlementResponse {
    /// Whether the payment settled.
    pub success: bool,
    /// Why it did not, as an x402 error code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// The paying address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// The settlement transaction (empty when settlement failed).
    pub transaction: String,
    /// CAIP-2 network the payment settled on.
    pub network: String,
    /// Amount actually charged, in the asset's smallest unit. Always present:
    /// under `upto` it can be less than the authorized ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// For a metered charge, the seller's signed usage record: what the buyer
    /// holds to dispute the charge on chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_record: Option<crate::metering::UsageRecord>,
    /// For a settlement plan, the plan the payment opened and its legs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanSettlement>,
}

/// The settlement plan a `plan` payment opened, as chain state holds it once
/// the plan transaction executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanSettlement {
    /// The plan id (hex).
    pub plan_id: String,
    /// Where the plan stands.
    pub status: tenzro_types::settlement::PlanStatus,
    /// Each leg's id (hex), by leg index.
    pub leg_ids: Vec<String>,
    /// The receipt of each decided leg. A plan whose legs are all on Tenzro
    /// decides in the opening transaction; one with legs elsewhere decides
    /// once their evidence is recorded, and its receipts are then read with
    /// `tenzro_getLegReceipt`.
    pub receipts: Vec<tenzro_types::settlement::LegReceipt>,
}

impl X402SettlementResponse {
    /// The response for a settled receipt. `None` when the receipt names no
    /// settlement transaction, which a receipt from the gateway always does.
    pub fn from_receipt(receipt: &PaymentReceipt) -> Option<Self> {
        let transaction = receipt.settlement_tx.clone()?;
        let text = |key: &str| {
            receipt
                .extra
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        Some(Self {
            success: true,
            error_reason: None,
            payer: text("payer_address").or_else(|| text("payer")),
            transaction,
            network: text("network").unwrap_or_else(|| receipt.chain.clone()),
            amount: Some(receipt.amount.to_string()),
            usage_record: receipt
                .extra
                .get(crate::metering::USAGE_RECORD_KEY)
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            plan: None,
        })
    }

    /// A failed settlement on `network`.
    pub fn failed(network: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            success: false,
            error_reason: Some(reason.into()),
            payer: None,
            transaction: String::new(),
            network: network.into(),
            amount: None,
            usage_record: None,
            plan: None,
        }
    }

    /// The `PAYMENT-RESPONSE` header value.
    pub fn to_base64(&self) -> Result<String> {
        encode_header(self)
    }

    /// Parse a `PAYMENT-RESPONSE` header value.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        decode_header(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn receipt(tx: Option<&str>) -> PaymentReceipt {
        let mut extra = HashMap::new();
        extra.insert("network".to_string(), serde_json::json!("tenzro:1337"));
        extra.insert(
            "payer_address".to_string(),
            serde_json::json!("ab".repeat(32)),
        );
        PaymentReceipt {
            receipt_id: "r".into(),
            protocol: "x402".into(),
            challenge_id: "c".into(),
            credential_id: "k".into(),
            amount: 700,
            asset: "TNZO".into(),
            settlement_tx: tx.map(str::to_string),
            chain: "tenzro".into(),
            settled_at: chrono::Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                String::new(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra,
        }
    }

    #[test]
    fn a_settled_receipt_names_its_transaction_network_and_charge() {
        let r = X402SettlementResponse::from_receipt(&receipt(Some("0xfeed"))).unwrap();
        assert!(r.success);
        assert_eq!(r.transaction, "0xfeed");
        assert_eq!(r.network, "tenzro:1337");
        assert_eq!(r.amount.as_deref(), Some("700"));
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("errorReason").is_none());
        assert_eq!(
            X402SettlementResponse::from_base64(&r.to_base64().unwrap()).unwrap(),
            r
        );
    }

    #[test]
    fn a_receipt_without_a_transaction_yields_no_response() {
        assert!(X402SettlementResponse::from_receipt(&receipt(None)).is_none());
    }
}
