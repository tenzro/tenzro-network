//! Charges a node collects for a payer, settled on the ledger.
//!
//! A charge is a `PayerSettle` transaction carrying the payer's own signed
//! [`PaymentAuthorization`]: the payer names the payee and a ceiling, the node
//! settles the metered amount up to that ceiling, and every validator
//! re-verifies the signature when the block executes. The node's key only
//! pays the gas; it has no authority over the payer's funds, and nothing moves
//! outside block execution.
//!
//! The authorization is checked here with the VM's own verifier, and the
//! payer's balance against committed state, before anything is submitted, so
//! a request the chain would refuse fails at once rather than in a block.

use std::sync::Arc;

use serde_json::Value;
use tenzro_payments::gateway::RailOutcome;
use tenzro_types::payment_authorization::PaymentAuthorization;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::TransactionType;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// A payer's signed consent to one payment, as a request carries it under
/// `payment`: `{ "payer", "payment_id", "authorization" }`.
#[derive(Debug, Clone)]
pub(crate) struct PayerPayment {
    /// Account debited.
    pub payer: Address,
    /// Idempotency key the payer signed; each settles once.
    pub payment_id: String,
    /// The payer's signature over the payment, its payee and its ceiling.
    pub authorization: PaymentAuthorization,
}

/// Parse a `payment` object.
pub(crate) fn parse_payment(value: &Value) -> Result<PayerPayment, JsonRpcError> {
    let payer = value
        .get("payer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err(-32602, "payment.payer is required"))?;
    let payer = tenzro_payments::payer_auth::parse_tenzro_address(payer)
        .map_err(|e| err(-32602, format!("payment.payer: {e}")))?;
    let payment_id = value
        .get("payment_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or_else(|| err(-32602, "payment.payment_id must be 1 to 128 bytes"))?
        .to_string();
    let authorization = value
        .get("authorization")
        .cloned()
        .ok_or_else(|| err(-32602, "payment.authorization is required"))
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|e| err(-32602, format!("payment.authorization: {e}")))
        })?;
    Ok(PayerPayment {
        payer,
        payment_id,
        authorization,
    })
}

/// The `payment` member of `params`, when the caller supplied one.
pub(crate) fn payment_param(params: &Value) -> Result<Option<PayerPayment>, JsonRpcError> {
    params.get("payment").map(parse_payment).transpose()
}

/// A settlement submitted to the ledger.
#[derive(Debug, Clone)]
pub(crate) struct LedgerCharge {
    /// Hash of the `PayerSettle` transaction.
    pub tx_hash: String,
    /// Whether it had executed when the wait ended; otherwise it is pending
    /// under `tx_hash`.
    pub executed: bool,
    /// What the payer was debited.
    pub amount: u128,
    /// The declared leg paid out of the amount to its own wallet.
    pub leg: u128,
    /// The network's settlement fee out of the rest, at the governed rate.
    pub network_fee: u128,
    /// What the payee is credited.
    pub payee_credit: u128,
    /// The payment record's reference, hex.
    pub pay_ref: String,
}

impl LedgerCharge {
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "tx_hash": self.tx_hash,
            "status": if self.executed { "settled" } else { "pending" },
            "amount": self.amount.to_string(),
            "declared_leg": self.leg.to_string(),
            "network_fee": self.network_fee.to_string(),
            "payee_credit": self.payee_credit.to_string(),
            "pay_ref": self.pay_ref,
        })
    }
}

/// How a settled amount divides: the declared leg paid to its own wallet,
/// the network's settlement fee on the rest, and the payee's credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Split {
    pub leg: u128,
    pub network_fee: u128,
    pub payee_credit: u128,
}

/// Divide `amount` as the chain will when it settles it with `margin`.
pub(crate) fn split(
    state: &dyn tenzro_vm::traits::VmState,
    amount: u128,
    margin: Option<&tenzro_types::payment_authorization::AppMargin>,
) -> Result<Split, JsonRpcError> {
    let leg = match margin {
        Some(m) => tenzro_vm::native::declared_leg(amount, m.margin_bps)
            .ok_or_else(|| err(-32602, "the declared leg overflows"))?,
        None => 0,
    };
    let price = amount - leg;
    let network_fee = tenzro_vm::native::settlement_fee(state, price);
    Ok(Split {
        leg,
        network_fee,
        payee_credit: price - network_fee,
    })
}

/// Refuse an authorization that does not carry exactly the leg this node
/// declares: the leg is paid from the payer's signed amount to its own
/// wallet, so the payer must have signed it, and a node declaring none takes
/// none.
pub(crate) fn check_declared(
    payment: &PayerPayment,
    declared: Option<tenzro_types::payment_authorization::AppMargin>,
) -> Result<(), JsonRpcError> {
    if payment.authorization.binding.app_margin != declared {
        return Err(err(
            -32001,
            match declared {
                Some(d) => format!(
                    "the payer's authorization must carry the fee this node declares: {} bps to 0x{}",
                    d.margin_bps,
                    hex::encode(d.app_wallet.as_bytes())
                ),
                None => "this node declares no fee; the authorization names one".to_string(),
            },
        ));
    }
    Ok(())
}

/// Settle `cost` from `payment`'s payer to `payee` in one `PayerSettle`,
/// with the leg this node `declared` on top of it (see [`check_declared`]):
/// the payee's price is `cost`, the leg is paid to its own wallet out of the
/// payer's signed amount, never out of a balance this node holds.
///
/// The network share comes out of `cost` under the governed settlement fee.
/// Refused before submission when
/// the authorization does not cover the debit or the payer cannot pay it, and
/// with the revert reason when the transaction fails in its block.
pub(crate) async fn settle(
    node: &Arc<TenzroNode>,
    payment: &PayerPayment,
    payee: Address,
    cost: u128,
    declared: Option<tenzro_types::payment_authorization::AppMargin>,
) -> Result<LedgerCharge, JsonRpcError> {
    if payment.payer == payee {
        return Err(err(-32602, "the payer cannot pay itself"));
    }
    check_declared(payment, declared)?;
    let amount = match declared {
        Some(d) => tenzro_vm::native::amount_with_leg(cost, d.margin_bps)
            .ok_or_else(|| err(-32602, "the declared leg overflows"))?,
        None => cost,
    };
    let submitter = node
        .ledger_submitter()
        .ok_or_else(|| err(-32000, "this node does not submit ledger transactions"))?;
    let state = tenzro_vm::StateAdapter::with_storage(node_storage(node)?);
    tenzro_vm::native::verify_payment_authorization(
        &state,
        submitter.chain_id(),
        &payment.payment_id,
        &payment.payer,
        &payee,
        amount,
        &payment.authorization,
        crate::calendar::now_ms(),
    )
    .map_err(|e| err(-32001, format!("payment authorization refused: {e}")))?;
    let balance = tenzro_vm::traits::VmState::get_balance(&state, payment.payer.as_bytes());
    if balance < amount {
        return Err(JsonRpcError {
            code: -32023,
            message: format!("the payer holds {balance}, the charge is {amount}"),
            data: Some(serde_json::json!({ "amount": amount.to_string() })),
        });
    }
    let tx = TransactionType::PayerSettle {
        payer: payment.payer,
        payee,
        amount,
        payment_id: payment.payment_id.clone(),
        authorization: payment.authorization.clone(),
    };
    let Split {
        leg,
        network_fee,
        payee_credit,
    } = split(
        &state,
        amount,
        payment.authorization.binding.app_margin.as_ref(),
    )?;
    let pay_ref = hex::encode(tenzro_types::payment_authorization::pay_ref(
        submitter.chain_id(),
        &payee,
        &payment.authorization.binding,
        &payment.payment_id,
    ));
    match submitter
        .settle(payee, tx)
        .await
        .map_err(|e| err(-32023, format!("settlement not submitted: {e}")))?
    {
        RailOutcome::Settled { reference } => Ok(LedgerCharge {
            tx_hash: reference,
            executed: true,
            amount,
            leg,
            network_fee,
            payee_credit,
            pay_ref,
        }),
        RailOutcome::Pending { reference } => Ok(LedgerCharge {
            tx_hash: reference,
            executed: false,
            amount,
            leg,
            network_fee,
            payee_credit,
            pay_ref,
        }),
        RailOutcome::Failed { reason } => {
            Err(err(-32023, format!("settlement reverted: {reason}")))
        }
    }
}

fn node_storage(node: &Arc<TenzroNode>) -> Result<Arc<dyn tenzro_storage::KvStore>, JsonRpcError> {
    node.storage()
        .cloned()
        .map(|s| s as Arc<dyn tenzro_storage::KvStore>)
        .ok_or_else(|| err(-32603, "storage not initialized"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::payment_authorization::{AppMargin, PaymentBinding};

    const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

    fn fee_leg() -> AppMargin {
        AppMargin {
            app_wallet: Address::new([0x9f; 32]),
            margin_bps: 250,
        }
    }

    fn payment(margin: Option<AppMargin>) -> PayerPayment {
        PayerPayment {
            payer: Address::new([0x01; 32]),
            payment_id: "call-1".into(),
            authorization: PaymentAuthorization {
                resellers: Vec::new(),
                public_key: Vec::new(),
                signature: tenzro_crypto::composite::CompositeSignature::classical(
                    tenzro_crypto::composite::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
                max_amount: u128::MAX,
                asset: "TNZO".into(),
                binding: PaymentBinding {
                    app_margin: margin,
                    ..Default::default()
                },
            },
        }
    }

    /// A platform's declared fee is its own leg on top of the price: the
    /// payee is credited the price net of the settlement fee, as if there
    /// were no platform, and the leg plus the fee plus the credit is the
    /// amount the payer signed.
    #[test]
    fn a_declared_fee_is_its_own_leg_on_top_of_the_price() {
        let dir = tempfile::tempdir().unwrap();
        let state = tenzro_vm::StateAdapter::with_storage(std::sync::Arc::new(
            tenzro_storage::RocksDbStore::open_default(dir.path()).unwrap(),
        ));
        let price = 4 * ONE_TNZO;
        let leg = fee_leg();
        let amount = tenzro_vm::native::amount_with_leg(price, leg.margin_bps).unwrap();
        assert_eq!(amount, price + price / 40);

        let s = split(&state, amount, Some(&leg)).unwrap();
        assert_eq!(
            s.leg,
            price / 40,
            "the leg is 2.5% of the price, on top of it"
        );
        let fee = tenzro_vm::native::settlement_fee(&state, price);
        assert_eq!(
            s.network_fee, fee,
            "the settlement fee is on the price alone"
        );
        assert_eq!(s.payee_credit, price - fee);
        assert_eq!(s.leg + s.network_fee + s.payee_credit, amount);

        // Without a leg the amount is the price.
        let plain = split(&state, price, None).unwrap();
        assert_eq!(plain.leg, 0);
        assert_eq!(plain.payee_credit, price - fee);

        // A price that does not divide evenly never leaves the payee short.
        let odd = 1_000_000_007u128;
        let amount = tenzro_vm::native::amount_with_leg(odd, leg.margin_bps).unwrap();
        let s = split(&state, amount, Some(&leg)).unwrap();
        assert!(amount - s.leg >= odd);
    }

    /// The payer must have signed exactly the fee the node declares: none,
    /// another wallet or another rate is refused, and a node declaring no
    /// fee takes none.
    #[test]
    fn the_payer_must_sign_exactly_the_declared_fee() {
        let leg = fee_leg();
        check_declared(&payment(Some(leg)), Some(leg)).expect("the signed fee");
        assert!(check_declared(&payment(None), Some(leg)).is_err());
        let elsewhere = AppMargin {
            app_wallet: Address::new([0x77; 32]),
            ..leg
        };
        assert!(check_declared(&payment(Some(elsewhere)), Some(leg)).is_err());
        let raised = AppMargin {
            margin_bps: 500,
            ..leg
        };
        assert!(check_declared(&payment(Some(raised)), Some(leg)).is_err());
        check_declared(&payment(None), None).expect("no fee declared, none signed");
        assert!(check_declared(&payment(Some(leg)), None).is_err());
    }
}
