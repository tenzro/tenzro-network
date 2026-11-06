//! Settlement SDK for Tenzro Network
//!
//! This module provides payment settlement and escrow functionality.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Settlement client for payment operations
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let settlement = client.settlement();
///
/// // Read the asset a payee is paid in
/// let preference = settlement.get_settlement_preference("did:tenzro:human:alice").await?;
/// println!("Preference: {preference}");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SettlementClient {
    rpc: Arc<RpcClient>,
}

impl SettlementClient {
    /// Creates a new settlement client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Settles a payment on the ledger: a `PayerSettle` transaction carrying
    /// the payer's own signed authorization (`request.payment`), which names
    /// the payee and a ceiling. The node relays it and pays the gas; it can
    /// move nothing the payer did not sign for.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig, SettlementRequest};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// # let payment = serde_json::json!({});
    /// let request = SettlementRequest {
    ///     payee: "0xprovider...".to_string(),
    ///     amount: 1_000_000,
    ///     payment,                  // {payer, payment_id, authorization}, signed by the payer
    /// };
    /// let response = client.settlement().settle(request).await?;
    /// println!("Settlement tx: {}", response.tx_hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn settle(&self, request: SettlementRequest) -> SdkResult<SettleResponse> {
        self.rpc
            .call(
                "tenzro_settle",
                serde_json::json!({
                    "payee": request.payee,
                    "amount": request.amount.to_string(),
                    "payment": request.payment,
                }),
            )
            .await
    }

    /// Inspects an escrow record by its 32-byte escrow_id.
    pub async fn get_escrow(&self, escrow_id: [u8; 32]) -> SdkResult<serde_json::Value> {
        let escrow_id_hex = format!("0x{}", hex::encode(escrow_id));
        self.rpc
            .call(
                "tenzro_getEscrow",
                serde_json::json!({ "escrow_id": escrow_id_hex }),
            )
            .await
    }

    /// Escrows funded by `payer`, in creation order from their `EscrowCreated`
    /// logs, each with its event cursor. Pass the page's `cursor` back as
    /// [`crate::types::PageRequest::from_cursor`] to continue with no gap.
    pub async fn list_escrows_by_payer(
        &self,
        payer: impl Into<String>,
        page: crate::types::PageRequest,
    ) -> SdkResult<EscrowPage> {
        let payer: String = payer.into();
        let mut params = page.to_params();
        params["payer"] = serde_json::Value::String(payer);
        self.rpc.call("tenzro_listEscrowsByPayer", params).await
    }

    /// Escrows held for `payee`, in creation order from their `EscrowCreated`
    /// logs, each with its event cursor. Pass the page's `cursor` back as
    /// [`crate::types::PageRequest::from_cursor`] to continue with no gap.
    pub async fn list_escrows_by_payee(
        &self,
        payee: impl Into<String>,
        page: crate::types::PageRequest,
    ) -> SdkResult<EscrowPage> {
        let payee: String = payee.into();
        let mut params = page.to_params();
        params["payee"] = serde_json::Value::String(payee);
        self.rpc.call("tenzro_listEscrowsByPayee", params).await
    }

    /// Open a payment channel over an escrow the payer already funded on the
    /// ledger with its own signed `CreateEscrow` transaction naming this
    /// node's payee. `channel_id` is that escrow's id (32 bytes, hex). The
    /// node checks the escrow on consensus state and returns the channel
    /// session.
    pub async fn open_payment_channel(&self, channel_id: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_openPaymentChannel",
                serde_json::json!({ "channel_id": channel_id }),
            )
            .await
    }

    /// Close a payment channel as its payer. `signer` holds the payer
    /// account's key and signs the close request once, for now; the node
    /// claims the highest voucher on chain and reports what is due.
    pub async fn close_payment_channel(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        channel_id: &str,
    ) -> SdkResult<ChannelClose> {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| crate::error::SdkError::InvalidParameter(format!("clock: {e}")))?
            .as_millis() as i64;
        let params = signed_owner_request(
            signer,
            "tenzro_closePaymentChannel",
            channel_id,
            timestamp_ms,
        )
        .await?;
        self.rpc.call("tenzro_closePaymentChannel", params).await
    }
}

/// The message an account owner signs for an owner-signed RPC request:
/// `tenzro/rpc-owner/v1`, 0, the method, 0, then the canonical bytes and the
/// request's `timestamp_ms` (i64 little-endian).
pub fn owner_request_message(method: &str, canonical: &[u8], timestamp_ms: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(48 + method.len() + canonical.len());
    message.extend_from_slice(b"tenzro/rpc-owner/v1");
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical);
    message.extend_from_slice(&timestamp_ms.to_le_bytes());
    message
}

/// `{channel_id, timestamp_ms, public_key, signature}`: the channel's payer
/// signs the 32-byte channel id under the account-owner context.
async fn signed_owner_request(
    signer: &dyn crate::wallet::HybridSigner,
    method: &str,
    channel_id: &str,
    timestamp_ms: i64,
) -> SdkResult<serde_json::Value> {
    use crate::wallet::{
        ACCOUNT_OWNER_SIGNATURE_CONTEXT, composite_message_representative, composite_signature_json,
    };
    let id: [u8; 32] = hex::decode(channel_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            crate::error::SdkError::InvalidParameter(
                "channel_id must be a 32-byte hex escrow id".into(),
            )
        })?;
    let message = owner_request_message(method, &id, timestamp_ms);
    let m_prime = composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, &message);
    let (p256, pq) = signer.sign_composite(&m_prime).await?;
    Ok(serde_json::json!({
        "channel_id": channel_id,
        "timestamp_ms": timestamp_ms,
        "public_key": hex::encode(signer.p256_public_key()),
        "signature": composite_signature_json(&p256, pq.as_deref()),
    }))
}

/// `tenzro_closePaymentChannel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelClose {
    /// The channel (escrow) id, hex.
    pub channel_id: String,
    /// `open`, `closing` or `closed`.
    pub status: String,
    /// What the node claims on chain (wei, decimal), when anything is due.
    pub claim_due: Option<String>,
}

/// A page of escrows, in creation order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowPage {
    /// The escrows, each with its event `cursor`.
    pub escrows: Vec<serde_json::Value>,
    /// Pass back as `from_cursor` to continue; `None` at the end.
    pub cursor: Option<String>,
}

/// Settlement request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRequest {
    /// Payee address (hex)
    pub payee: String,
    /// Amount (wei)
    pub amount: u128,
    /// The payer's signed authorization: `{payer, payment_id, authorization}`,
    /// where `authorization` is the payer's `PaymentAuthorization` naming this
    /// payee and a ceiling of at least the amount (plus any app margin)
    pub payment: serde_json::Value,
}

/// Settlement response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleResponse {
    /// Hash of the `PayerSettle` transaction
    pub tx_hash: String,
    /// `settled` once it executed, `pending` while it has not
    pub status: String,
    /// What the payer was debited (wei, decimal)
    pub amount: String,
    /// The network's settlement fee (wei, decimal)
    pub network_fee: String,
    /// What the payee was credited (wei, decimal)
    pub payee_credit: String,
    /// The payer's account (0x-hex)
    #[serde(default)]
    pub payer: Option<String>,
    /// The payee's account (0x-hex)
    #[serde(default)]
    pub payee: Option<String>,
    /// The payment id the payer's authorization names
    #[serde(default)]
    pub payment_id: Option<String>,
}

impl SettlementClient {
    /// A meter's bond by its 32-byte id (hex): owner, amount, withdrawal
    /// request time and the dispute window, or `None` when it has none.
    pub async fn get_meter_bond(
        &self,
        meter_id: &str,
    ) -> crate::error::SdkResult<Option<MeterBond>> {
        self.rpc
            .call(
                "tenzro_getMeterBond",
                serde_json::json!({ "meter_id": meter_id }),
            )
            .await
    }

    /// Calls `tenzro_redeemSealedDelivery`: redeem sealed delivery.
    pub async fn redeem_sealed_delivery(
        &self,
        escrow_id: &str,
        network_escrow_id: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_redeemSealedDelivery", serde_json::json!({ "escrow_id": escrow_id, "network_escrow_id": network_escrow_id })).await
    }

    /// Calls `tenzro_updatePaymentChannel`: update payment channel.
    pub async fn update_payment_channel(
        &self,
        voucher: serde_json::Value,
        charge: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_updatePaymentChannel",
                serde_json::json!({ "voucher": voucher, "charge": charge }),
            )
            .await
    }
}

impl SettlementClient {
    /// Calls `tenzro_getSettlementPreference`: get settlement preference.
    pub async fn get_settlement_preference(
        &self,
        payee_did: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getSettlementPreference",
                serde_json::json!({ "payee_did": payee_did }),
            )
            .await
    }
}

/// `tenzro_getMeterBond`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterBond {
    /// The meter id, hex.
    pub meter_id: String,
    /// The bonding account, hex.
    pub owner: String,
    /// The bond (wei, decimal).
    pub amount: String,
    /// When the owner asked to withdraw, Unix milliseconds.
    pub withdrawal_requested_at_ms: Option<u64>,
    /// The governed dispute window, milliseconds.
    pub dispute_window_ms: Option<u64>,
}
