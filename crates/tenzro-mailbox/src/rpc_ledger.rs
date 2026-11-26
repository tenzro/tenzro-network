//! The ledger as a node serves it over JSON-RPC.
//!
//! Every call is one any caller may make: `tenzro_getEscrow`,
//! `tenzro_getAccountSigningKey` and `tenzro_resolveDidDocument`. The node
//! is the operator's own, beside the mailbox; no sign-in is involved. Each
//! call is bounded in time and in the size of the reply it reads.

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{Value, json};
use tenzro_crypto::{CompositePublicKey, account_slot};

use crate::error::MailboxError;
use crate::service::{EscrowView, Ledger, SigningKey};

/// Longest a node may take to answer one call.
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Largest reply read from a node: a DID document with many keys fits.
const MAX_REPLY_BYTES: usize = 256 * 1024;
/// P-256 keys of a DID document tried for one request.
const MAX_DID_KEYS: usize = 4;

/// A node's JSON-RPC endpoint, read as the mailbox's ledger.
pub struct RpcLedger {
    http: reqwest::Client,
    url: String,
}

fn bytes_of(value: &Value) -> Option<Vec<u8>> {
    hex::decode(value.as_str()?.trim_start_matches("0x")).ok()
}

/// An account in its 32-byte slot: a 20-byte address followed by zeros, or
/// 32 bytes as they are.
fn slot_of(value: &Value) -> Option<[u8; 32]> {
    let bytes = bytes_of(value)?;
    let mut slot = [0u8; 32];
    match bytes.len() {
        20 | 32 => slot[..bytes.len()].copy_from_slice(&bytes),
        _ => return None,
    }
    Some(slot)
}

fn amount_of(value: &Value) -> Option<u128> {
    match value {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// The P-256 key (`x || y`) a DID document's verification method carries,
/// from its multibase or its JWK form.
fn p256_of(method: &Value) -> Option<Vec<u8>> {
    if method.get("type")?.as_str()? != "EcdsaSecp256r1VerificationKey2019" {
        return None;
    }
    if let Some(jwk) = method.get("publicKeyJwk") {
        let part = |name: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk.get(name)?.as_str()?)
                .ok()
        };
        let (x, y) = (part("x")?, part("y")?);
        return (x.len() == 32 && y.len() == 32).then(|| [x, y].concat());
    }
    let multibase = method.get("publicKeyMultibase")?.as_str()?;
    let bytes = bs58::decode(multibase.strip_prefix('z')?).into_vec().ok()?;
    match bytes.len() {
        64 => Some(bytes),
        65 if bytes[0] == 0x04 => Some(bytes[1..].to_vec()),
        _ => None,
    }
}

impl RpcLedger {
    /// The ledger served at `url`, a node's JSON-RPC endpoint.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(CALL_TIMEOUT)
                .connect_timeout(CALL_TIMEOUT)
                .build()
                .expect("a client with timeouts"),
            url: url.into(),
        }
    }

    /// The result of `method`, or `None` when the node answers with an
    /// error: the record asked for does not exist, or the node refuses the
    /// request. Only a node that cannot be reached or answers with something
    /// else than JSON-RPC is a failure.
    async fn call(&self, method: &str, params: Value) -> Result<Option<Value>, MailboxError> {
        let ledger = |e: reqwest::Error| MailboxError::Ledger(format!("{method}: {e}"));
        let mut response = self
            .http
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .map_err(ledger)?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(ledger)? {
            if body.len() + chunk.len() > MAX_REPLY_BYTES {
                return Err(MailboxError::Ledger(format!(
                    "{method}: the reply passes {MAX_REPLY_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let answer: Value = serde_json::from_slice(&body)
            .map_err(|e| MailboxError::Ledger(format!("{method}: {e}")))?;
        if answer.get("error").is_some_and(|e| !e.is_null()) {
            return Ok(None);
        }
        answer
            .get("result")
            .cloned()
            .map(Some)
            .ok_or_else(|| MailboxError::Ledger(format!("{method}: neither result nor error")))
    }
}

#[async_trait]
impl Ledger for RpcLedger {
    async fn account_key(
        &self,
        public_key: &[u8],
        account: &[u8; 32],
    ) -> Result<Option<SigningKey>, MailboxError> {
        let params = json!({
            "public_key": hex::encode(public_key),
            "account": hex::encode(account),
        });
        let Some(result) = self.call("tenzro_getAccountSigningKey", params).await? else {
            return Ok(None);
        };
        let key = bytes_of(&result["p256"])
            .filter(|p256| p256 == public_key)
            .and_then(|p256| {
                let ml_dsa = match &result["ml_dsa"] {
                    Value::Null => None,
                    other => Some(bytes_of(other)?),
                };
                CompositePublicKey::new(p256, ml_dsa).ok()
            })
            .ok_or_else(|| {
                MailboxError::Ledger("tenzro_getAccountSigningKey: malformed key".to_string())
            })?;
        Ok(Some(SigningKey {
            key,
            rp_id: result["rp_id"].as_str().map(str::to_string),
        }))
    }

    async fn did_key(
        &self,
        did: &str,
        public_key: &[u8],
    ) -> Result<Option<SigningKey>, MailboxError> {
        let Some(document) = self
            .call("tenzro_resolveDidDocument", json!({ "did": did }))
            .await?
        else {
            return Ok(None);
        };
        let methods = document["verificationMethod"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        // A key acts for the DID when it acts for the account one of the
        // DID's own P-256 keys names: that key itself, or a passkey the
        // account's keystore links.
        for own in methods.iter().filter_map(p256_of).take(MAX_DID_KEYS) {
            if let Some(key) = self.account_key(public_key, &account_slot(&own)).await? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    async fn escrow(&self, escrow_id: &[u8; 32]) -> Result<Option<EscrowView>, MailboxError> {
        let params = json!({ "escrow_id": hex::encode(escrow_id) });
        let Some(escrow) = self.call("tenzro_getEscrow", params).await? else {
            return Ok(None);
        };
        if bytes_of(&escrow["escrow_id"]).as_deref() != Some(escrow_id.as_slice()) {
            return Err(MailboxError::Ledger(
                "tenzro_getEscrow: the node answered with another escrow".to_string(),
            ));
        }
        if escrow["status"].as_str() != Some("Funded") {
            return Ok(None);
        }
        let view = (|| {
            Some(EscrowView {
                payer: slot_of(&escrow["payer"])?,
                payee: slot_of(&escrow["payee"])?,
                amount: amount_of(&escrow["amount"])?,
                claimed: amount_of(&escrow["claimed"])?,
                expires_at_ms: escrow["expires_at"].as_u64()?,
            })
        })();
        view.map(Some)
            .ok_or_else(|| MailboxError::Ledger("tenzro_getEscrow: malformed escrow".to_string()))
    }
}
