//! Passkey account keystores, held in consensus state.
//!
//! A passkey account is its devices plus its keystore on the ledger: the
//! passkeys that may act for it, its policy, its recovery signers and any
//! recovery in progress. Every node answers from the same record, so any
//! linked device works through any node. Changes are `KeystoreUpdate`
//! transactions approved over [`keystore_digest`], which every SDK computes
//! the same way; any account may send and pay for one. Passkeys approve in a
//! browser or on a device (WebAuthn); a hardware recovery signer approves
//! with [`KeystoreClient::approve_recovery`].

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
use crate::types::Address;
use crate::wallet::{HybridSigner, composite_message_representative, composite_signature_json};

/// Context recovery signers approve a recovery under.
pub const RECOVERY_APPROVAL_SIGNATURE_CONTEXT: &[u8] = b"tenzro/identity/recovery-approval";

const UPDATE_DOMAIN: &[u8] = b"tenzro/keystore-update/v1";

fn invalid(msg: impl Into<String>) -> SdkError {
    SdkError::InvalidParameter(msg.into())
}

fn bytes(v: &Value, name: &str) -> SdkResult<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| invalid(format!("{name} is hex")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|_| invalid(format!("{name} is hex")))
}

fn field(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn flag(v: &Value, name: &str) -> SdkResult<u8> {
    v.as_bool()
        .map(u8::from)
        .ok_or_else(|| invalid(format!("{name} is a boolean")))
}

fn text<'a>(v: &'a Value, name: &str) -> SdkResult<&'a str> {
    v.as_str()
        .ok_or_else(|| invalid(format!("{name} is a string")))
}

fn credential(out: &mut Vec<u8>, c: &Value) -> SdkResult<()> {
    field(out, text(&c["rp_id"], "rp_id")?.as_bytes());
    field(out, &bytes(&c["credential_id"], "credential_id")?);
    field(out, &bytes(&c["public_key"], "public_key")?);
    field(out, &bytes(&c["aaguid"], "aaguid")?);
    out.push(flag(&c["backup_eligible"], "backup_eligible")?);
    out.push(flag(&c["backup_state"], "backup_state")?);
    field(out, text(&c["label"], "label")?.as_bytes());
    Ok(())
}

const RECOVERY_CODE_DOMAIN: &[u8] = b"tenzro/keystore/recovery-code/v1";
const RECOVERY_CLAIM_DOMAIN: &[u8] = b"tenzro/keystore/recovery-claim/v1";

/// The commitment an account holds on chain `chain_id` for its one-time
/// recovery code (`code`, 32 bytes hex, kept by its holder);
/// `set_recovery_code` sets it. `account` is hex.
pub fn recovery_code_commitment(chain_id: u64, account: &str, code: &str) -> SdkResult<[u8; 32]> {
    Ok(Sha256::new()
        .chain_update(RECOVERY_CODE_DOMAIN)
        .chain_update(chain_id.to_le_bytes())
        .chain_update(bytes(&json!(account), "account")?)
        .chain_update(bytes(&json!(code), "code")?)
        .finalize()
        .into())
}

/// The claim on chain `chain_id` binding the recovery code to the passkey
/// `credential` (its JSON form) that will join: sent first, by another
/// account, as `claim_recovery_code`; the code is revealed with
/// `recover_with_code` once the claim has aged.
pub fn recovery_code_claim(
    chain_id: u64,
    account: &str,
    code: &str,
    credential_json: &Value,
) -> SdkResult<[u8; 32]> {
    let mut c = Vec::new();
    credential(&mut c, credential_json)?;
    Ok(Sha256::new()
        .chain_update(RECOVERY_CLAIM_DOMAIN)
        .chain_update(chain_id.to_le_bytes())
        .chain_update(bytes(&json!(account), "account")?)
        .chain_update(bytes(&json!(code), "code")?)
        .chain_update(&c)
        .finalize()
        .into())
}

/// The canonical bytes of a keystore change (its JSON form) an approval
/// covers.
pub fn encode_keystore_op(op: &Value) -> SdkResult<Vec<u8>> {
    let mut out = Vec::new();
    match op {
        Value::String(s) if s == "cancel_recovery" => out.push(5),
        Value::String(s) if s == "finish_recovery" => out.push(6),
        Value::Object(m) if m.len() == 1 => {
            let (kind, v) = m.iter().next().expect("one entry");
            match kind.as_str() {
                "add_credential" => {
                    out.push(1);
                    credential(&mut out, &v["credential"])?;
                }
                "remove_credential" => {
                    out.push(2);
                    field(&mut out, &bytes(&v["credential_id"], "credential_id")?);
                }
                "set_recovery" => {
                    out.push(3);
                    let threshold = v["threshold"]
                        .as_u64()
                        .ok_or_else(|| invalid("threshold"))?
                        as u32;
                    let signers = v["signers"].as_array().ok_or_else(|| invalid("signers"))?;
                    out.extend_from_slice(&threshold.to_be_bytes());
                    out.extend_from_slice(&(signers.len() as u32).to_be_bytes());
                    for s in signers {
                        field(&mut out, text(&s["rp_id"], "rp_id")?.as_bytes());
                        field(&mut out, &bytes(&s["public_key"], "public_key")?);
                        field(&mut out, &bytes(&s["aaguid"], "aaguid")?);
                        out.push(flag(&s["backup_eligible"], "backup_eligible")?);
                        out.push(flag(&s["backup_state"], "backup_state")?);
                        out.push(match text(&s["role"], "role")? {
                            "recovery_key" => 1,
                            "email_verifier" => 2,
                            "device" => 3,
                            other => return Err(invalid(format!("unknown recovery role {other}"))),
                        });
                        field(&mut out, text(&s["label"], "label")?.as_bytes());
                    }
                }
                "start_recovery" => {
                    out.push(4);
                    credential(&mut out, &v["credential"])?;
                }
                "set_policy" => {
                    out.push(7);
                    out.push(match text(&v["policy"], "policy")? {
                        "single_credential" => 1,
                        "two_credentials" => 2,
                        other => return Err(invalid(format!("unknown policy {other}"))),
                    });
                }
                "set_recovery_code" => {
                    out.push(8);
                    match &v["commitment"] {
                        Value::Null => field(&mut out, &[]),
                        c => field(&mut out, &bytes(c, "commitment")?),
                    }
                }
                "claim_recovery_code" => {
                    out.push(9);
                    field(&mut out, &bytes(&v["claim"], "claim")?);
                }
                "recover_with_code" => {
                    out.push(10);
                    field(&mut out, &bytes(&v["code"], "code")?);
                    credential(&mut out, &v["credential"])?;
                }
                other => return Err(invalid(format!("unknown keystore change {other}"))),
            }
        }
        _ => return Err(invalid("a keystore change is one of its named variants")),
    }
    Ok(out)
}

/// What every approval of `op` on `account` on chain `chain_id` signs,
/// given the commitment of the record it changes:
/// `SHA-256(domain ‖ chain id ‖ account ‖ commitment ‖ op)`, the chain id as
/// 8 bytes little-endian. A chain refuses a change approved for another.
/// `account` and `previous_commitment` are hex.
pub fn keystore_digest(
    chain_id: u64,
    account: &str,
    previous_commitment: &str,
    op: &Value,
) -> SdkResult<[u8; 32]> {
    let account = bytes(&json!(account), "account")?;
    let previous = bytes(&json!(previous_commitment), "previous_commitment")?;
    let mut h = Sha256::new();
    h.update(UPDATE_DOMAIN);
    h.update(chain_id.to_le_bytes());
    h.update((account.len() as u32).to_be_bytes());
    h.update(&account);
    h.update((previous.len() as u32).to_be_bytes());
    h.update(&previous);
    h.update(encode_keystore_op(op)?);
    Ok(h.finalize().into())
}

/// Reads keystores and sends their changes.
#[derive(Clone)]
pub struct KeystoreClient {
    rpc: Arc<RpcClient>,
}

impl KeystoreClient {
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// `tenzro_getKeystore`: the keystore of `account`, with its commitment;
    /// with `anchor`, the genesis record of an account that has none on chain.
    pub async fn get_keystore(&self, account: &str, anchor: Option<Value>) -> SdkResult<Value> {
        let mut params = json!({ "account": account });
        if let Some(anchor) = anchor {
            params["anchor"] = anchor;
        }
        self.rpc.call("tenzro_getKeystore", params).await
    }

    /// `tenzro_resolveCredential`: the accounts whose keystore links the
    /// passkey with this credential id (hex), registered on `rp_id`.
    pub async fn resolve_credential(&self, credential_id: &str, rp_id: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_resolveCredential",
                json!({ "credential_id": credential_id, "rp_id": rp_id }),
            )
            .await
    }

    /// Add `signer`'s approval as a recovery signer of the account.
    pub async fn approve_recovery(
        &self,
        mut update: Value,
        signer: &dyn HybridSigner,
    ) -> SdkResult<Value> {
        let chain_id = update["chain_id"]
            .as_u64()
            .ok_or_else(|| invalid("chain_id is the chain the change is for"))?;
        let digest = keystore_digest(
            chain_id,
            text(&update["account"], "account")?,
            text(&update["previous_commitment"], "previous_commitment")?,
            &update["op"],
        )?;
        let m_prime =
            composite_message_representative(RECOVERY_APPROVAL_SIGNATURE_CONTEXT, &digest);
        let (p256, ml_dsa) = signer.sign_composite(&m_prime).await?;
        let approval = json!({
            "public_key": hex::encode(signer.p256_public_key()),
            "signature": composite_signature_json(&p256, ml_dsa.as_deref()),
        });
        update["approvals"]
            .as_array_mut()
            .ok_or_else(|| invalid("approvals is a list"))?
            .push(approval);
        Ok(update)
    }

    /// Send `update` (a `KeystoreUpdate` with its approvals), signed and paid
    /// for by `sender`; with `from`, from that account. Without it the sender
    /// is a sponsor paying for an account with no balance: it authorizes
    /// nothing, the change carrying the passkeys' approvals. The fee is paid
    /// at `gas_price`, or at the node's current price (`eth_gasPrice`).
    pub async fn send(
        &self,
        sender: &dyn HybridSigner,
        update: Value,
        from: Option<Address>,
        gas_price: Option<u64>,
    ) -> SdkResult<Value> {
        let mut tx = TypedTransaction::new(TxKind::KeystoreUpdate, json!({ "update": update }))?;
        if let Some(from) = from {
            tx = tx.from(from);
        }
        if let Some(price) = gas_price {
            tx = tx.gas_price(price);
        }
        TypedTxClient::new(self.rpc.clone()).send(sender, &tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_is_sent_as_the_network_encodes_it() {
        let raw = include_str!("../../fixtures/keystore/encoding.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        for case in v["cases"].as_array().unwrap() {
            let tx =
                TypedTransaction::new(TxKind::KeystoreUpdate, json!({ "update": case["update"] }))
                    .unwrap();
            assert_eq!(
                tx.tx_type(),
                json!({ "KeystoreUpdate": { "update": case["encoded"] } })
            );
        }
    }

    #[test]
    fn the_digest_matches_the_shared_vector() {
        let raw = include_str!("../../fixtures/keystore/digest.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 11);
        for case in cases {
            let digest = keystore_digest(
                v["chain_id"].as_u64().unwrap(),
                v["account"].as_str().unwrap(),
                v["previous_commitment"].as_str().unwrap(),
                &case["op"],
            )
            .unwrap();
            assert_eq!(
                hex::encode(digest),
                case["digest"].as_str().unwrap(),
                "{}",
                case["op"]
            );
        }
    }

    #[test]
    fn the_recovery_code_helpers_match_the_shared_vector() {
        let raw = include_str!("../../fixtures/keystore/digest.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let chain_id = v["chain_id"].as_u64().unwrap();
        let account = v["account"].as_str().unwrap();
        let cases = v["cases"].as_array().unwrap();
        let code = "77".repeat(32);
        let credential = &cases[10]["op"]["recover_with_code"]["credential"];
        assert_eq!(
            hex::encode(recovery_code_commitment(chain_id, account, &code).unwrap()),
            cases[8]["op"]["set_recovery_code"]["commitment"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(recovery_code_claim(chain_id, account, &code, credential).unwrap()),
            cases[9]["op"]["claim_recovery_code"]["claim"]
                .as_str()
                .unwrap()
        );
        assert_ne!(
            recovery_code_commitment(chain_id + 1, account, &code).unwrap(),
            recovery_code_commitment(chain_id, account, &code).unwrap()
        );
    }
}
