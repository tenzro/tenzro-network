//! Payment SDK for Tenzro Network
//!
//! This module provides payment challenges, credential checks
//! and direct settlement.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::wallet::{
    HybridSigner, account_address, composite_message_representative, composite_signature_json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Payment client: challenges, credential checks and ledger settlement
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let payment_client = client.payment();
///
/// // Price one US dollar in TNZO
/// let quote = payment_client.quote(1_000_000, &["TNZO"]).await?;
/// println!("{quote}");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PaymentClient {
    rpc: Arc<RpcClient>,
}

impl PaymentClient {
    /// Creates a new payment client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Creates a payment challenge for a resource (server-side). The node
    /// stamps it with its chain id; pass the returned challenge to the payer,
    /// who signs a credential for it with [`sign_credential`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let payment_client = client.payment();
    /// let challenge = payment_client.create_challenge(
    ///     "/api/inference/gemma4-9b",
    ///     1000,
    ///     "TNZO",
    ///     "mpp",
    ///     None,
    /// ).await?;
    /// println!("Challenge ID: {}", challenge.challenge_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        protocol: &str,
        recipient: Option<&str>,
    ) -> SdkResult<PaymentChallenge> {
        self.rpc
            .call(
                "tenzro_createPaymentChallenge",
                challenge_request(resource, amount, asset, protocol, recipient),
            )
            .await
    }

    /// Checks a credential against its challenge without settling
    /// (`tenzro_verifyPayment`): `verified`, and the amount and account it
    /// would debit, or the `reason` it would not pay.
    pub async fn verify_payment(
        &self,
        credential: &PaymentCredential,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_verifyPayment", credential_params(credential)?)
            .await
    }

    /// Settles a payment on the ledger with the payer's own signed
    /// authorization (`payment`: `{payer, payment_id, authorization}` naming
    /// `to` and a ceiling of at least `amount`). The node relays it as an
    /// `PayerSettle` transaction and pays the gas.
    ///
    /// # Arguments
    ///
    /// * `to` - Payee address (hex)
    /// * `amount` - Payment amount (wei)
    /// * `payment` - The payer's signed authorization
    pub async fn settle_payment(
        &self,
        to: &str,
        amount: u128,
        payment: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_settle",
                serde_json::json!({
                    "payee": to,
                    // A decimal string carries the whole u128 range; a JSON
                    // number would lose precision above 2^53 in many parsers.
                    "amount": amount.to_string(),
                    "payment": payment,
                }),
            )
            .await
    }

    /// What `usd_e6` (USD micro-units) costs in each of `accept` now (TNZO
    /// when empty), with the settlement fee each pays in kind, or a coded
    /// reason an asset cannot settle now:
    /// `{usd_e6, unit, rate_epoch, assets}`. [`crate::ledger_pay`] reads it.
    pub async fn quote(&self, usd_e6: u64, accept: &[&str]) -> SdkResult<serde_json::Value> {
        let mut params = serde_json::json!({ "usd_e6": usd_e6 });
        if !accept.is_empty() {
            params["accept"] = serde_json::json!(accept);
        }
        self.rpc.call("tenzro_quotePayment", params).await
    }
}

/// A payment challenge as the node issues it (`tenzro_createPaymentChallenge`
/// and the HTTP 402 response). `extra` carries the chain id the node stamped,
/// and the payee's quote digest and USD price when the challenge was quoted;
/// the payer's signature covers them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChallenge {
    /// Challenge ID
    pub challenge_id: String,
    /// Protocol (mpp or x402)
    pub protocol: String,
    /// Resource being accessed
    pub resource: String,
    /// Required payment amount, in the asset's smallest unit
    #[serde(with = "crate::types::u128_wire")]
    pub amount: u128,
    /// Asset to pay in
    pub asset: String,
    /// Payee address (hex, 20 or 32 bytes)
    pub recipient: String,
    /// Chain the payment settles on
    #[serde(default)]
    pub chain: String,
    /// Expiry (RFC 3339)
    #[serde(default)]
    pub expires_at: String,
    /// Protocol-specific data the node stamped (`chain_id`, `quote_digest`,
    /// `usd_e6`, `intent`, ...)
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A payer's signed answer to a [`PaymentChallenge`], in the shape the pay
/// endpoints parse (`{"credential": PaymentCredential}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredential {
    /// Credential ID
    pub credential_id: String,
    /// Challenge this credential answers
    pub challenge_id: String,
    /// Protocol (mpp or x402)
    pub protocol: String,
    /// Payer DID, bound to the signing key
    pub payer_did: String,
    /// Payer account (hex, 32 bytes), derived from the signing key
    pub payer_address: String,
    /// The charge
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Composite signature over the authorization message
    /// ([`crate::wallet::composite_signature_json`])
    pub signature: serde_json::Value,
    /// `public_key` (the payer's P-256 key, hex) and, for a metered
    /// credential, `upto_max` (the signed ceiling, decimal)
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Signature context of a payment authorization.
pub const PAYMENT_AUTHORIZATION_CONTEXT: &[u8] = b"tenzro/payment/authorization";

/// Domain tag prefixed to every payment authorization message.
pub const PAYMENT_AUTHORIZATION_DOMAIN: &[u8] = b"tenzro/payment-authorization";

/// Domain of the digest of the requested resource.
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"tenzro/request";

fn invalid(msg: impl Into<String>) -> SdkError {
    SdkError::InvalidParameter(msg.into())
}

/// A Tenzro address from 20 or 32 bytes of hex; 20 bytes fill the leading
/// bytes.
fn tenzro_address(value: &str) -> SdkResult<[u8; 32]> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))
        .map_err(|e| invalid(format!("address '{value}' is not hex: {e}")))?;
    let mut out = [0u8; 32];
    match bytes.len() {
        20 => out[..20].copy_from_slice(&bytes),
        32 => out.copy_from_slice(&bytes),
        n => {
            return Err(invalid(format!(
                "address '{value}' is {n} bytes; a Tenzro address is 20 or 32 bytes"
            )));
        }
    }
    Ok(out)
}

/// The message a payer signs to authorize `max_amount` against `challenge`,
/// exactly as the node rebuilds it: the chain, the challenge id, payer and
/// payee, the ceiling, the asset, and what is paid for (the request digest of
/// the resource, the quote digest and the USD price, zero when unquoted, and
/// the application margin the challenge names, if any).
pub fn authorization_message(
    challenge: &PaymentChallenge,
    payer: &[u8; 32],
    max_amount: u128,
) -> SdkResult<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let chain_id = challenge
        .extra
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            invalid(format!(
                "challenge {} carries no chain_id; it was not issued by a node",
                challenge.challenge_id
            ))
        })?;
    let payee = tenzro_address(&challenge.recipient)?;
    let quote_digest: [u8; 32] = match challenge.extra.get("quote_digest") {
        None => [0u8; 32],
        Some(v) => v
            .as_str()
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("quote_digest is 32 bytes of hex"))?,
    };
    let usd_e6 = match challenge.extra.get("usd_e6") {
        None => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| invalid("usd_e6 must be an unsigned integer"))?,
    };
    let app_margin = app_margin(challenge)?;
    let mut h = Sha256::new();
    h.update(REQUEST_DIGEST_DOMAIN);
    h.update(challenge.resource.as_bytes());
    let request_digest: [u8; 32] = h.finalize().into();

    let id = challenge.challenge_id.as_bytes();
    let asset = challenge.asset.as_bytes();
    let mut m = Vec::with_capacity(
        PAYMENT_AUTHORIZATION_DOMAIN.len() + 8 + 4 + id.len() + 64 + 16 + 4 + asset.len() + 72 + 37,
    );
    m.extend_from_slice(PAYMENT_AUTHORIZATION_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(&(id.len() as u32).to_le_bytes());
    m.extend_from_slice(id);
    m.extend_from_slice(payer);
    m.extend_from_slice(&payee);
    m.extend_from_slice(&max_amount.to_le_bytes());
    m.extend_from_slice(&(asset.len() as u32).to_le_bytes());
    m.extend_from_slice(asset);
    m.extend_from_slice(&request_digest);
    m.extend_from_slice(&quote_digest);
    m.extend_from_slice(&usd_e6.to_le_bytes());
    match app_margin {
        None => m.push(0),
        Some((app_wallet, margin_bps)) => {
            m.push(1);
            m.extend_from_slice(&app_wallet);
            m.extend_from_slice(&margin_bps.to_le_bytes());
        }
    }
    Ok(m)
}

/// The application's developer margin a challenge asks the payer to sign:
/// `app_wallet` and a non-zero `margin_bps` together, or neither.
fn app_margin(challenge: &PaymentChallenge) -> SdkResult<Option<([u8; 32], u32)>> {
    let margin_bps = match challenge.extra.get("margin_bps") {
        None => 0,
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| invalid("margin_bps must be a u32"))?,
    };
    let app_wallet = match challenge.extra.get("app_wallet") {
        None => None,
        Some(v) => {
            Some(tenzro_address(v.as_str().ok_or_else(|| {
                invalid("app_wallet must be a hex string")
            })?)?)
        }
    };
    match (app_wallet, margin_bps) {
        (None, 0) => Ok(None),
        (Some(wallet), bps) if bps > 0 => Ok(Some((wallet, bps))),
        _ => Err(invalid(
            "a developer margin names both a non-zero margin_bps and an app_wallet",
        )),
    }
}

/// Sign a credential for `challenge` with the payer's hardware key.
///
/// The charge is the challenge amount; `max_amount` is the ceiling signed
/// (defaults to the charge). A ceiling above the charge is recorded as
/// `upto_max` and makes a metered credential. The paying account is
/// `account` (its 32-byte slot) when given: a passkey account whose keystore
/// on chain links the signer's passkey, such as the account every device of
/// a wallet acts for. Otherwise it is the one the signer's P-256 key derives.
pub async fn sign_credential(
    challenge: &PaymentChallenge,
    signer: &dyn HybridSigner,
    payer_did: &str,
    max_amount: Option<u128>,
    account: Option<[u8; 32]>,
) -> SdkResult<PaymentCredential> {
    let amount = challenge.amount;
    let max_amount = max_amount.unwrap_or(amount);
    if max_amount < amount {
        return Err(invalid(format!(
            "max_amount {max_amount} is below the challenge amount {amount}"
        )));
    }
    let public_key = signer.p256_public_key();
    let payer = account.unwrap_or_else(|| account_address(&public_key));
    let message = authorization_message(challenge, &payer, max_amount)?;
    let m_prime = composite_message_representative(PAYMENT_AUTHORIZATION_CONTEXT, &message);
    let (p256, ml_dsa) = signer.sign_composite(&m_prime).await?;
    let mut extra = serde_json::Map::new();
    extra.insert(
        "public_key".into(),
        serde_json::json!(hex::encode(public_key)),
    );
    if max_amount != amount {
        extra.insert("upto_max".into(), serde_json::json!(max_amount.to_string()));
    }
    Ok(PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: challenge.protocol.to_ascii_lowercase(),
        payer_did: payer_did.to_string(),
        payer_address: hex::encode(payer),
        amount,
        asset: challenge.asset.clone(),
        signature: composite_signature_json(&p256, ml_dsa.as_deref()),
        extra,
    })
}

/// `{"credential": credential}`, the parameters every credential endpoint
/// parses.
pub fn credential_params(credential: &PaymentCredential) -> SdkResult<serde_json::Value> {
    let value =
        serde_json::to_value(credential).map_err(|e| invalid(format!("credential: {e}")))?;
    Ok(serde_json::json!({ "credential": value }))
}

/// The parameters of `tenzro_createPaymentChallenge`: the object the node
/// reads, the amount as a decimal string so the whole u128 range survives.
pub fn challenge_request(
    resource: &str,
    amount: u128,
    asset: &str,
    protocol: &str,
    recipient: Option<&str>,
) -> serde_json::Value {
    let mut p = serde_json::json!({
        "resource": resource,
        "amount": amount.to_string(),
        "asset": asset,
        "protocol": protocol,
    });
    if let Some(r) = recipient {
        p["recipient"] = serde_json::json!(r);
    }
    p
}

/// A payment receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Receipt ID
    #[serde(default)]
    pub receipt_id: String,
    /// Protocol used (mpp or x402)
    #[serde(default)]
    pub protocol: String,
    /// Amount paid, in the smallest unit
    #[serde(default, with = "crate::types::u128_wire")]
    pub amount: u128,
    /// Asset used
    #[serde(default)]
    pub asset: String,
    /// MPP session ID (if applicable)
    #[serde(default)]
    pub session_id: Option<String>,
}

impl PaymentClient {
    /// Calls `tenzro_mirrorSettlement`: mirror settlement.
    pub async fn mirror_settlement(
        &self,
        interaction: serde_json::Value,
        targets: serde_json::Value,
        primary_committed: bool,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_mirrorSettlement", serde_json::json!({ "interaction": interaction, "targets": targets, "primary_committed": primary_committed })).await
    }
}

impl PaymentClient {
    /// Choose the asset `payee_did` is paid in (`keep_inbound` or `tnzo`).
    /// The payee's hardware `signer` signs the change as the account owner;
    /// its key must be one of the DID's authentication keys.
    pub async fn set_settlement_preference(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        payee_did: &str,
        asset: &str,
    ) -> SdkResult<serde_json::Value> {
        use crate::wallet::{
            ACCOUNT_OWNER_SIGNATURE_CONTEXT, composite_message_representative,
            composite_signature_json,
        };
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        let preimage = settlement_preference_preimage(payee_did, asset, timestamp_ms);
        let m_prime = composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, &preimage);
        let (p256, pq) = signer.sign_composite(&m_prime).await?;
        self.rpc
            .call(
                "tenzro_setSettlementPreference",
                serde_json::json!({
                    "payee_did": payee_did,
                    "asset": asset,
                    "timestamp_ms": timestamp_ms,
                    "public_key": hex::encode(signer.p256_public_key()),
                    "signature": composite_signature_json(&p256, pq.as_deref()),
                }),
            )
            .await
    }
}

/// The message a settlement-preference change signs, identical to
/// `tenzro_types::settlement::settlement_preference_preimage`: the domain
/// followed by each field length-prefixed (u64 little-endian).
pub fn settlement_preference_preimage(payee_did: &str, asset: &str, timestamp_ms: i64) -> Vec<u8> {
    let mut preimage = b"tenzro/settlement-preference/v1".to_vec();
    for field in [
        payee_did.as_bytes(),
        asset.as_bytes(),
        &timestamp_ms.to_le_bytes()[..],
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_le_bytes());
        preimage.extend_from_slice(field);
    }
    preimage
}
