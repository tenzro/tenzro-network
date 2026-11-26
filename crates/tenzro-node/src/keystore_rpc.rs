//! Reads of passkey account keystores (see [`tenzro_types::keystore`]).
//!
//! Every answer comes from committed chain state, so every node gives the
//! same one: no node, site or wallet provider holds anything an account needs
//! that the ledger does not. Changes are `KeystoreUpdate` transactions,
//! submitted like any other.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use tenzro_types::keystore::{KeystoreAnchor, KeystoreRecord};

use crate::node::TenzroNode;
use crate::passkey_rpc::{decode_hex, parse_params};
use crate::rpc::JsonRpcError;

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// The time of the latest executed block: the clock a block judges a
/// keystore's time-bound rules by, never this machine's.
async fn chain_time_ms(node: &Arc<TenzroNode>) -> Result<u64, JsonRpcError> {
    use tenzro_storage::traits::BlockStore as _;
    let error = |message: String| JsonRpcError {
        code: -32603,
        message,
        data: None,
    };
    let storage = node
        .storage()
        .ok_or_else(|| error("this node holds no chain state".to_string()))?;
    let blocks = tenzro_storage::block_store::BlockStoreImpl::new(storage.clone())
        .map_err(|e| error(format!("Storage error: {e}")))?;
    let block = blocks
        .latest_block()
        .await
        .map_err(|e| error(format!("Storage error: {e}")))?
        .ok_or_else(|| error("this node has executed no block".to_string()))?;
    Ok(block.header.timestamp.0.max(0) as u64)
}

fn chain_state(node: &Arc<TenzroNode>) -> Result<tenzro_vm::StateAdapter, JsonRpcError> {
    node.webauthn_validator()
        .map(|v| v.state())
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "this node holds no chain state".to_string(),
            data: None,
        })
}

#[derive(Debug, Deserialize)]
struct GetKeystoreRequest {
    /// The account, 20-byte hex.
    account: String,
    /// The account's first passkey, for an account with no keystore on chain
    /// yet: the answer is then its genesis record.
    #[serde(default)]
    anchor: Option<KeystoreAnchor>,
}

/// `tenzro_getKeystore`: the keystore of a passkey account, its commitment
/// (what the account's next `KeystoreUpdate` names as `previous_commitment`)
/// and whether its passkeys may spend now.
pub(crate) async fn handle_get_keystore(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetKeystoreRequest = parse_params(params)?;
    let account = tenzro_vm::keystore::account20(&decode_hex(&req.account)?)
        .ok_or_else(|| invalid("account is a 20-byte address"))?;
    let state = chain_state(node)?;
    let (record, on_chain): (Option<KeystoreRecord>, bool) =
        match tenzro_vm::keystore::read_record(&state, &account) {
            Some(record) => (Some(record), true),
            None => match req.anchor {
                Some(anchor) => {
                    let genesis = KeystoreRecord::genesis(&anchor);
                    if genesis.account != account {
                        return Err(invalid("the anchor's passkey does not derive the account"));
                    }
                    (Some(genesis), false)
                }
                None => (None, false),
            },
        };
    let now = chain_time_ms(node).await?;
    Ok(match record {
        Some(r) => json!({
            "account": hex::encode(account),
            "on_chain": on_chain,
            "commitment": hex::encode(r.commitment()),
            "independent_roots": r.independent_roots_at(now),
            "may_spend": r.may_spend(now),
            "keystore": r,
        }),
        None => json!({
            "account": hex::encode(account),
            "on_chain": false,
            "keystore": Value::Null,
        }),
    })
}

#[derive(Debug, Deserialize)]
struct AccountSigningKeyRequest {
    /// The P-256 public key (`x || y`), hex.
    public_key: String,
    /// The account the key would sign for, hex.
    account: String,
}

/// `tenzro_getAccountSigningKey`: the public keys `public_key` signs with
/// for `account` now, as a signature by it is judged in a block: the P-256
/// key, the ML-DSA-65 key enrolled for it, and the relying party a passkey
/// assertion by it must be for when the account's keystore links it. An
/// error says why the key does not act for the account.
pub(crate) async fn handle_get_account_signing_key(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: AccountSigningKeyRequest = parse_params(params)?;
    let public_key = decode_hex(&req.public_key)?;
    let account = decode_hex(&req.account)?;
    let state = chain_state(node)?;
    let (key, rp_id) = tenzro_vm::keystore::account_signing_key(
        &state,
        &public_key,
        &account,
        chain_time_ms(node).await?,
    )
    .map_err(|e| JsonRpcError {
        code: -32004,
        message: e.to_string(),
        data: None,
    })?;
    Ok(json!({
        "p256": hex::encode(&key.p256),
        "ml_dsa": key.pq.as_ref().map(hex::encode),
        "rp_id": rp_id,
    }))
}

#[derive(Debug, Deserialize)]
struct ResolveCredentialRequest {
    /// The WebAuthn credential id, hex.
    credential_id: String,
    /// The relying party the passkey is registered on.
    rp_id: String,
}

/// `tenzro_resolveCredential`: the accounts whose keystore links a passkey,
/// found from its credential id and relying party alone.
pub(crate) async fn handle_resolve_credential(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ResolveCredentialRequest = parse_params(params)?;
    let credential_id = decode_hex(&req.credential_id)?;
    if credential_id.is_empty() {
        return Err(invalid("credential_id is empty"));
    }
    let state = chain_state(node)?;
    if !tenzro_types::keystore::valid_rp_id(&req.rp_id) {
        return Err(invalid(
            "rp_id must be the relying party the passkey is registered on, a lowercase DNS name",
        ));
    }
    Ok(
        json!({ "accounts": tenzro_vm::keystore::resolve_credential(&state, &req.rp_id, &credential_id) }),
    )
}
