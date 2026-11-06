//! Typed transactions for every consensus transaction type, signed
//! client-side.
//!
//! A [`TypedTransaction`] names its [`TxKind`] and carries the variant's
//! fields as JSON. [`TypedTxClient::send`] fills in the envelope (sender,
//! nonce, chain, validity window), asks the node for the signing payload,
//! checks that the payload is the transaction it asked for, signs the digest
//! with the caller's hybrid key and submits it. The node never signs: it only
//! encodes, and an encoding that does not match what the caller built is
//! refused before anything is signed.

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::types::Address;
use crate::wallet::{
    HybridSigner, TRANSACTION_SIGNATURE_CONTEXT, account_address, composite_message_representative,
    composite_signature_json,
};

/// Every consensus transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxKind {
    Transfer,
    ContractDeploy,
    ContractCall,
    AgentRegister,
    AgentExecute,
    ModelInference,
    TeeProviderRegister,
    GovernancePropose,
    GovernanceVote,
    GovernanceVeto,
    GovernancePause,
    GovernanceExecute,
    Funding,
    CreateEscrow,
    ReleaseEscrow,
    RefundEscrow,
    PauseAgent,
    QuarantineAgent,
    TerminateAgent,
    PostAgentBond,
    IncreaseAgentBond,
    WithdrawAgentBond,
    PostComputeBond,
    IncreaseComputeBond,
    WithdrawComputeBond,
    FinalizeComputeBondWithdrawal,
    PayInsuranceClaim,
    PayerSettle,
    ClaimEscrow,
    ClaimEscrowPreimage,
    ClaimEscrowStream,
    PostMeterBond,
    WithdrawMeterBond,
    DisputeMeteredCharge,
    TreasuryDeposit,
    IncreaseValidatorStake,
    RegisterValidator,
    ReportCheckpointEquivocation,
    ExitValidator,
    UpdateValidatorMetadata,
    RegisterIdentity,
    AttestZkProof,
    SlaAttest,
    ComputeClaim,
    RecordCheckpointSigners,
    AgentAuditCommit,
    LiftAgentQuarantine,
    AgentAuditFlag,
    RevokeDelegatedAgent,
    SetAgentTerms,
    AgentAct,
    FeeRateSubmit,
    InferenceFault,
    Bridge,
    Token,
    Stake,
    RemoteGrantSettle,
    Payment,
    GovernanceVetoSignal,
    GovernanceVetoWithdraw,
    GovernanceConcern,
    UpgradeReady,
    GovernanceSecurityDisclosure,
    SettlementPlan,
    BeaconContribute,
    DaRetention,
    AccountKeys,
    KeystoreUpdate,
    /// A change to a DID document's service entries, approved by the DID's root.
    IdentityServices,
    ExternalEvm,
    ExternalSvm,
    /// An identity revoked on its root's authority.
    RevokeIdentity,
    /// A generic registry entry put, bonded or retired.
    Registry,
    /// A delegated agent's top-up allowance set or cancelled by its controller.
    SetAgentTopUp,
    /// A delegated agent's wallet refilled within its controller's allowance.
    TopUpAgent,
    /// TNZO moved from a delegated agent's wallet back to its controller.
    ReclaimAgentFunds,
    /// The sender's consensus key replaced, effective at the next epoch.
    RotateValidatorKey,
    /// A proof about the sending identity's hardware.
    HardwareProof,
    /// The machine identity of the sending validator, named on chain.
    RegisterValidatorMachine,
    /// A key-release operation on a model's release policy.
    KeyRelease,
    /// A training proof operation on a round's signed receipt.
    TrainingProof,
    /// A TPM attestation attached to a machine root registered without one.
    AttachMachineAttestation,
    /// A governance-sponsored validator bond operation: matured unbonding
    /// sponsored stake returned to the treasury.
    SponsoredBond,
    /// An operation on the sender's own opt-in outflow policy.
    AccountOutflow,
}

impl TxKind {
    /// Every kind, in the order the network declares them.
    pub const ALL: [TxKind; 84] = [
        TxKind::Transfer,
        TxKind::ContractDeploy,
        TxKind::ContractCall,
        TxKind::AgentRegister,
        TxKind::AgentExecute,
        TxKind::ModelInference,
        TxKind::TeeProviderRegister,
        TxKind::GovernancePropose,
        TxKind::GovernanceVote,
        TxKind::GovernanceVeto,
        TxKind::GovernancePause,
        TxKind::GovernanceExecute,
        TxKind::Funding,
        TxKind::CreateEscrow,
        TxKind::ReleaseEscrow,
        TxKind::RefundEscrow,
        TxKind::PauseAgent,
        TxKind::QuarantineAgent,
        TxKind::TerminateAgent,
        TxKind::PostAgentBond,
        TxKind::IncreaseAgentBond,
        TxKind::WithdrawAgentBond,
        TxKind::PostComputeBond,
        TxKind::IncreaseComputeBond,
        TxKind::WithdrawComputeBond,
        TxKind::FinalizeComputeBondWithdrawal,
        TxKind::PayInsuranceClaim,
        TxKind::PayerSettle,
        TxKind::ClaimEscrow,
        TxKind::ClaimEscrowPreimage,
        TxKind::ClaimEscrowStream,
        TxKind::PostMeterBond,
        TxKind::WithdrawMeterBond,
        TxKind::DisputeMeteredCharge,
        TxKind::TreasuryDeposit,
        TxKind::IncreaseValidatorStake,
        TxKind::RegisterValidator,
        TxKind::ReportCheckpointEquivocation,
        TxKind::ExitValidator,
        TxKind::UpdateValidatorMetadata,
        TxKind::RegisterIdentity,
        TxKind::AttestZkProof,
        TxKind::SlaAttest,
        TxKind::ComputeClaim,
        TxKind::RecordCheckpointSigners,
        TxKind::AgentAuditCommit,
        TxKind::LiftAgentQuarantine,
        TxKind::AgentAuditFlag,
        TxKind::RevokeDelegatedAgent,
        TxKind::SetAgentTerms,
        TxKind::AgentAct,
        TxKind::FeeRateSubmit,
        TxKind::InferenceFault,
        TxKind::Bridge,
        TxKind::Token,
        TxKind::Stake,
        TxKind::RemoteGrantSettle,
        TxKind::Payment,
        TxKind::GovernanceVetoSignal,
        TxKind::GovernanceVetoWithdraw,
        TxKind::GovernanceConcern,
        TxKind::UpgradeReady,
        TxKind::GovernanceSecurityDisclosure,
        TxKind::SettlementPlan,
        TxKind::BeaconContribute,
        TxKind::DaRetention,
        TxKind::AccountKeys,
        TxKind::KeystoreUpdate,
        TxKind::IdentityServices,
        TxKind::ExternalEvm,
        TxKind::ExternalSvm,
        TxKind::RevokeIdentity,
        TxKind::Registry,
        TxKind::SetAgentTopUp,
        TxKind::TopUpAgent,
        TxKind::ReclaimAgentFunds,
        TxKind::RotateValidatorKey,
        TxKind::HardwareProof,
        TxKind::RegisterValidatorMachine,
        TxKind::KeyRelease,
        TxKind::TrainingProof,
        TxKind::AttachMachineAttestation,
        TxKind::SponsoredBond,
        TxKind::AccountOutflow,
    ];

    /// The name the network encodes the kind under.
    pub fn as_str(self) -> &'static str {
        match self {
            TxKind::Transfer => "Transfer",
            TxKind::ContractDeploy => "ContractDeploy",
            TxKind::ContractCall => "ContractCall",
            TxKind::AgentRegister => "AgentRegister",
            TxKind::AgentExecute => "AgentExecute",
            TxKind::ModelInference => "ModelInference",
            TxKind::TeeProviderRegister => "TeeProviderRegister",
            TxKind::GovernancePropose => "GovernancePropose",
            TxKind::GovernanceVote => "GovernanceVote",
            TxKind::GovernanceVeto => "GovernanceVeto",
            TxKind::GovernancePause => "GovernancePause",
            TxKind::GovernanceExecute => "GovernanceExecute",
            TxKind::Funding => "Funding",
            TxKind::CreateEscrow => "CreateEscrow",
            TxKind::ReleaseEscrow => "ReleaseEscrow",
            TxKind::RefundEscrow => "RefundEscrow",
            TxKind::PauseAgent => "PauseAgent",
            TxKind::QuarantineAgent => "QuarantineAgent",
            TxKind::TerminateAgent => "TerminateAgent",
            TxKind::PostAgentBond => "PostAgentBond",
            TxKind::IncreaseAgentBond => "IncreaseAgentBond",
            TxKind::WithdrawAgentBond => "WithdrawAgentBond",
            TxKind::PostComputeBond => "PostComputeBond",
            TxKind::IncreaseComputeBond => "IncreaseComputeBond",
            TxKind::WithdrawComputeBond => "WithdrawComputeBond",
            TxKind::FinalizeComputeBondWithdrawal => "FinalizeComputeBondWithdrawal",
            TxKind::PayInsuranceClaim => "PayInsuranceClaim",
            TxKind::PayerSettle => "PayerSettle",
            TxKind::ClaimEscrow => "ClaimEscrow",
            TxKind::ClaimEscrowPreimage => "ClaimEscrowPreimage",
            TxKind::ClaimEscrowStream => "ClaimEscrowStream",
            TxKind::PostMeterBond => "PostMeterBond",
            TxKind::WithdrawMeterBond => "WithdrawMeterBond",
            TxKind::DisputeMeteredCharge => "DisputeMeteredCharge",
            TxKind::TreasuryDeposit => "TreasuryDeposit",
            TxKind::IncreaseValidatorStake => "IncreaseValidatorStake",
            TxKind::RegisterValidator => "RegisterValidator",
            TxKind::ReportCheckpointEquivocation => "ReportCheckpointEquivocation",
            TxKind::ExitValidator => "ExitValidator",
            TxKind::UpdateValidatorMetadata => "UpdateValidatorMetadata",
            TxKind::RegisterIdentity => "RegisterIdentity",
            TxKind::AttestZkProof => "AttestZkProof",
            TxKind::SlaAttest => "SlaAttest",
            TxKind::ComputeClaim => "ComputeClaim",
            TxKind::RecordCheckpointSigners => "RecordCheckpointSigners",
            TxKind::AgentAuditCommit => "AgentAuditCommit",
            TxKind::LiftAgentQuarantine => "LiftAgentQuarantine",
            TxKind::AgentAuditFlag => "AgentAuditFlag",
            TxKind::RevokeDelegatedAgent => "RevokeDelegatedAgent",
            TxKind::SetAgentTerms => "SetAgentTerms",
            TxKind::AgentAct => "AgentAct",
            TxKind::FeeRateSubmit => "FeeRateSubmit",
            TxKind::InferenceFault => "InferenceFault",
            TxKind::Bridge => "Bridge",
            TxKind::Token => "Token",
            TxKind::Stake => "Stake",
            TxKind::RemoteGrantSettle => "RemoteGrantSettle",
            TxKind::Payment => "Payment",
            TxKind::GovernanceVetoSignal => "GovernanceVetoSignal",
            TxKind::GovernanceVetoWithdraw => "GovernanceVetoWithdraw",
            TxKind::GovernanceConcern => "GovernanceConcern",
            TxKind::UpgradeReady => "UpgradeReady",
            TxKind::GovernanceSecurityDisclosure => "GovernanceSecurityDisclosure",
            TxKind::SettlementPlan => "SettlementPlan",
            TxKind::BeaconContribute => "BeaconContribute",
            TxKind::DaRetention => "DaRetention",
            TxKind::AccountKeys => "AccountKeys",
            TxKind::KeystoreUpdate => "KeystoreUpdate",
            TxKind::IdentityServices => "IdentityServices",
            TxKind::RevokeIdentity => "RevokeIdentity",
            TxKind::ExternalEvm => "ExternalEvm",
            TxKind::ExternalSvm => "ExternalSvm",
            TxKind::Registry => "Registry",
            TxKind::SetAgentTopUp => "SetAgentTopUp",
            TxKind::TopUpAgent => "TopUpAgent",
            TxKind::ReclaimAgentFunds => "ReclaimAgentFunds",
            TxKind::RotateValidatorKey => "RotateValidatorKey",
            TxKind::HardwareProof => "HardwareProof",
            TxKind::RegisterValidatorMachine => "RegisterValidatorMachine",
            TxKind::KeyRelease => "KeyRelease",
            TxKind::TrainingProof => "TrainingProof",
            TxKind::AttachMachineAttestation => "AttachMachineAttestation",
            TxKind::SponsoredBond => "SponsoredBond",
            TxKind::AccountOutflow => "AccountOutflow",
        }
    }

    /// Whether the kind carries fields. Only `ExitValidator` does not.
    pub fn has_fields(self) -> bool {
        !matches!(self, TxKind::ExitValidator)
    }
}

/// A transaction of one [`TxKind`], before its envelope and signature.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedTransaction {
    /// The transaction type.
    pub kind: TxKind,
    /// The type's fields, as the network encodes them.
    pub fields: Value,
    /// The recipient field of the envelope; the system address when unset.
    pub to: Option<Address>,
    /// The sender: a passkey account whose keystore on chain links the
    /// signer's passkey, such as the account every device of a wallet acts
    /// for. The account the signer's P-256 key names when unset.
    pub from: Option<Address>,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price, smallest TNZO unit. The node's current price
    /// (`eth_gasPrice`) when unset.
    pub gas_price: Option<u64>,
}

/// Validity window the SDK signs with: five minutes, inside the network's
/// caps for every transaction class.
const VALIDITY_MS: i64 = 300_000;

impl TypedTransaction {
    /// A transaction of `kind` with `fields`: a JSON object for every kind but
    /// `ExitValidator`, which takes `Value::Null`.
    pub fn new(kind: TxKind, fields: Value) -> SdkResult<Self> {
        match (kind.has_fields(), &fields) {
            (true, Value::Object(_)) | (false, Value::Null) => {}
            (true, _) => {
                return Err(SdkError::InvalidParameter(format!(
                    "{} takes a JSON object of fields",
                    kind.as_str()
                )));
            }
            (false, _) => {
                return Err(SdkError::InvalidParameter(format!(
                    "{} takes no fields",
                    kind.as_str()
                )));
            }
        }
        Ok(Self {
            kind,
            fields,
            to: None,
            from: None,
            gas_limit: 500_000,
            gas_price: None,
        })
    }

    /// Set the envelope's recipient.
    pub fn to(mut self, to: Address) -> Self {
        self.to = Some(to);
        self
    }

    /// Send from `from`, a passkey account whose keystore links the signer.
    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    /// Set the gas limit.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set the gas price.
    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// The `tx_type` the network decodes: `{"Kind": fields}`, or the bare
    /// name for a kind without fields.
    pub fn tx_type(&self) -> Value {
        if self.kind.has_fields() {
            let mut fields = self.fields.clone();
            if self.kind == TxKind::KeystoreUpdate {
                // A credential the change adds carries `added_at_ms` (zero;
                // the chain sets it), as the node's signing payload does.
                if let Some(op) = fields
                    .pointer_mut("/update/op")
                    .and_then(Value::as_object_mut)
                {
                    for name in ["add_credential", "start_recovery"] {
                        if let Some(credential) = op
                            .get_mut(name)
                            .and_then(|b| b.get_mut("credential"))
                            .and_then(Value::as_object_mut)
                        {
                            credential.entry("added_at_ms").or_insert(json!(0));
                        }
                    }
                }
            }
            let mut tagged = serde_json::Map::new();
            tagged.insert(self.kind.as_str().to_string(), fields);
            Value::Object(tagged)
        } else {
            Value::String(self.kind.as_str().to_string())
        }
    }
}

/// The envelope fields of one signing, kept to check the node's payload.
struct Envelope {
    chain_id: u64,
    from: [u8; 32],
    to: [u8; 32],
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    timestamp: i64,
    valid_until: i64,
}

/// The node a [`TypedTxClient`] reads nonces and signing payloads from and
/// submits to. [`RpcClient`] reaches it over HTTP; an application embedding a
/// node implements this over its in-process dispatch.
#[async_trait::async_trait]
pub trait NodeRpc: Send + Sync {
    /// One JSON-RPC call, answering its `result`.
    async fn call_value(&self, method: &str, params: Value) -> SdkResult<Value>;
}

#[async_trait::async_trait]
impl NodeRpc for RpcClient {
    async fn call_value(&self, method: &str, params: Value) -> SdkResult<Value> {
        self.call(method, params).await
    }
}

/// A typed transaction checked against the node's encoding and not signed:
/// the request [`TypedTxClient::send`] would submit, without `public_key` and
/// `signature`, and the SHA-256 digest a signer would sign.
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedTransaction {
    /// The `tenzro_sendRawTransaction` params, unsigned.
    pub request: Value,
    /// The digest the node and the SDK agree on.
    pub digest: [u8; 32],
}

/// Signs and submits [`TypedTransaction`]s.
#[derive(Clone)]
pub struct TypedTxClient {
    rpc: Arc<dyn NodeRpc>,
}

impl TypedTxClient {
    /// Creates a new typed transaction client over HTTP.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Creates a typed transaction client over any [`NodeRpc`].
    pub fn over(rpc: Arc<dyn NodeRpc>) -> Self {
        Self { rpc }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> SdkResult<T> {
        let value = self.rpc.call_value(method, params).await?;
        serde_json::from_value(value).map_err(|e| SdkError::RpcError(format!("{method}: {e}")))
    }

    /// A dry run of `tx` sent from the account `from`: reads the nonce, chain
    /// id and gas price the node reports, asks the node to encode the signing
    /// payload, and checks that the encoding is the transaction built here.
    /// Returns the request and the digest a signer would sign; nothing is
    /// signed or submitted. A failed read or a payload that does not match is
    /// an error, as it is in [`TypedTxClient::send`].
    pub async fn prepare(
        &self,
        from: Address,
        tx: &TypedTransaction,
    ) -> SdkResult<PreparedTransaction> {
        let from = tx.from.as_ref().map(|a| a.0).unwrap_or(from.0);
        self.prepare_from(from, tx).await
    }

    async fn prepare_from(
        &self,
        from: [u8; 32],
        tx: &TypedTransaction,
    ) -> SdkResult<PreparedTransaction> {
        let from_hex = format!("0x{}", hex::encode(from));
        let mut to = [0u8; 32];
        if let Some(addr) = &tx.to {
            to.copy_from_slice(addr.as_bytes());
        }
        let nonce_hex: String = self.call("tenzro_getNonce", json!([from_hex])).await?;
        let chain_hex: String = self.call("eth_chainId", json!([])).await?;
        let gas_price = match tx.gas_price {
            Some(price) => price,
            None => parse_hex_u64(&self.call::<String>("eth_gasPrice", json!([])).await?)?,
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SdkError::InvalidParameter(e.to_string()))?
            .as_millis() as i64;
        let env = Envelope {
            chain_id: parse_hex_u64(&chain_hex)?,
            from,
            to,
            nonce: parse_hex_u64(&nonce_hex)?,
            gas_limit: tx.gas_limit,
            gas_price,
            timestamp,
            valid_until: timestamp + VALIDITY_MS,
        };
        let request = json!({
            "from": from_hex,
            "to": format!("0x{}", hex::encode(env.to)),
            "nonce": env.nonce,
            "chain_id": env.chain_id,
            "gas_limit": env.gas_limit,
            "gas_price": env.gas_price,
            "timestamp": env.timestamp,
            "valid_until": env.valid_until,
            "tx_type": tx.tx_type(),
        });
        let payload: Value = self
            .call("tenzro_getSigningPayload", request.clone())
            .await?;
        let digest = check_signing_payload(&env, &tx.tx_type(), &payload)?;
        Ok(PreparedTransaction { request, digest })
    }

    /// Sign `tx` with `signer` and submit it. Returns the node's answer to
    /// `tenzro_sendRawTransaction`.
    pub async fn send(&self, signer: &dyn HybridSigner, tx: &TypedTransaction) -> SdkResult<Value> {
        self.send_via("tenzro_sendRawTransaction", signer, tx).await
    }

    /// Sign `tx` with `signer` and submit it through `method`, which takes
    /// the params `tenzro_sendRawTransaction` takes (`tenzro_revokeIdentity`
    /// for a `RevokeIdentity` transaction).
    pub async fn send_via(
        &self,
        method: &str,
        signer: &dyn HybridSigner,
        tx: &TypedTransaction,
    ) -> SdkResult<Value> {
        let public_key = signer.p256_public_key();
        let from = tx
            .from
            .as_ref()
            .map(|a| a.0)
            .unwrap_or_else(|| account_address(&public_key));
        let PreparedTransaction {
            mut request,
            digest,
        } = self.prepare_from(from, tx).await?;
        let m_prime = composite_message_representative(TRANSACTION_SIGNATURE_CONTEXT, &digest);
        let (signature, pq_signature) = signer.sign_composite(&m_prime).await?;
        request["public_key"] = json!(hex::encode(public_key));
        request["signature"] = composite_signature_json(&signature, pq_signature.as_deref());
        self.call(method, request).await
    }
}

fn parse_hex_u64(s: &str) -> SdkResult<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| SdkError::RpcError(format!("bad hex {s}: {e}")))
}

fn mismatch(what: &str) -> SdkError {
    SdkError::RpcError(format!(
        "the node's signing payload does not match the transaction: {what}"
    ))
}

/// The digest to sign, once the node's payload is shown to be the
/// transaction `env` and `tx_type` describe.
///
/// A plain transaction's digest is SHA-256 over the envelope and the
/// canonical `tx_type` encoding, which the node supplies and which must decode
/// to `tx_type`. A privileged one is signed over a typed preimage, which must
/// carry these envelope fields and this action; its digest is SHA-256 of the
/// preimage bytes.
fn check_signing_payload(env: &Envelope, tx_type: &Value, payload: &Value) -> SdkResult<[u8; 32]> {
    let digest_hex = payload["digest"]
        .as_str()
        .ok_or_else(|| mismatch("no digest"))?;
    let claimed: [u8; 32] = hex::decode(digest_hex)
        .ok()
        .and_then(|d| d.try_into().ok())
        .ok_or_else(|| mismatch("digest is not 32 bytes of hex"))?;
    let digest: [u8; 32] = match payload["kind"].as_str() {
        Some("plain") => {
            let encoded = payload["tx_type_json"]
                .as_str()
                .ok_or_else(|| mismatch("no tx_type encoding"))?;
            let decoded: Value = serde_json::from_str(encoded)
                .map_err(|_| mismatch("tx_type encoding is not JSON"))?;
            if decoded != *tx_type {
                return Err(mismatch("tx_type"));
            }
            let mut h = Sha256::new();
            h.update(env.chain_id.to_le_bytes());
            h.update(env.from);
            h.update(env.to);
            h.update(env.nonce.to_le_bytes());
            h.update(env.gas_limit.to_le_bytes());
            h.update(env.gas_price.to_le_bytes());
            h.update(env.timestamp.to_le_bytes());
            h.update(env.valid_until.to_le_bytes());
            h.update(encoded.as_bytes());
            h.finalize().into()
        }
        Some("typed_action") => {
            let bytes = payload["preimage"]
                .as_str()
                .ok_or_else(|| mismatch("no preimage"))?;
            let p: Value =
                serde_json::from_str(bytes).map_err(|_| mismatch("preimage is not JSON"))?;
            let checks = [
                ("chain_id", json!(env.chain_id)),
                ("from", json!(hex::encode(env.from))),
                ("to", json!(hex::encode(env.to))),
                ("nonce", json!(env.nonce)),
                ("gas_limit", json!(env.gas_limit)),
                ("gas_price", json!(env.gas_price)),
                ("timestamp", json!(env.timestamp)),
                ("valid_until", json!(env.valid_until)),
                ("action", tx_type.clone()),
            ];
            for (field, want) in checks {
                if p[field] != want {
                    return Err(mismatch(field));
                }
            }
            Sha256::digest(bytes.as_bytes()).into()
        }
        _ => return Err(mismatch("unknown payload kind")),
    };
    if digest != claimed {
        return Err(mismatch("digest"));
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope {
            chain_id: 1337,
            from: [1; 32],
            to: [2; 32],
            nonce: 7,
            gas_limit: 500_000,
            gas_price: 1,
            timestamp: 1_000,
            valid_until: 2_000,
        }
    }

    #[test]
    fn every_kind_has_a_distinct_name_and_only_exit_validator_has_no_fields() {
        let names: std::collections::HashSet<_> = TxKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), TxKind::ALL.len());
        assert!(
            TxKind::ALL
                .iter()
                .filter(|k| !k.has_fields())
                .eq([TxKind::ExitValidator].iter())
        );
        assert!(TypedTransaction::new(TxKind::Transfer, json!(5)).is_err());
        assert_eq!(
            TypedTransaction::new(TxKind::ExitValidator, Value::Null)
                .unwrap()
                .tx_type(),
            json!("ExitValidator")
        );
    }

    #[test]
    fn a_plain_payload_is_checked_against_the_transaction() {
        let tx_type = json!({"Transfer": {"amount": 5}});
        let encoded = r#"{"Transfer":{"amount":5}}"#;
        let e = env();
        let mut h = Sha256::new();
        for part in [
            &e.chain_id.to_le_bytes()[..],
            &e.from,
            &e.to,
            &e.nonce.to_le_bytes(),
            &e.gas_limit.to_le_bytes(),
            &e.gas_price.to_le_bytes(),
            &e.timestamp.to_le_bytes(),
            &e.valid_until.to_le_bytes(),
            encoded.as_bytes(),
        ] {
            h.update(part);
        }
        let digest: [u8; 32] = h.finalize().into();
        let payload =
            json!({"kind": "plain", "tx_type_json": encoded, "digest": hex::encode(digest)});
        assert_eq!(
            check_signing_payload(&e, &tx_type, &payload).unwrap(),
            digest
        );

        let other = json!({"kind": "plain", "tx_type_json": r#"{"Transfer":{"amount":6}}"#, "digest": hex::encode(digest)});
        assert!(
            check_signing_payload(&e, &tx_type, &other).is_err(),
            "a different amount is refused"
        );
    }

    #[test]
    fn a_typed_action_preimage_must_carry_this_action() {
        let e = env();
        let tx_type = json!({"GovernanceVote": {"proposal_id": "p", "vote": true}});
        let preimage = json!({
            "domain": "tenzro/typed-action", "class": "governance", "chain_id": 1337,
            "from": hex::encode(e.from), "to": hex::encode(e.to), "nonce": 7, "gas_limit": 500_000,
            "gas_price": 1, "timestamp": 1_000, "valid_until": 2_000, "action": tx_type,
            "approvals": [],
        })
        .to_string();
        let digest: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
        let payload =
            json!({"kind": "typed_action", "preimage": preimage, "digest": hex::encode(digest)});
        assert_eq!(
            check_signing_payload(&e, &tx_type, &payload).unwrap(),
            digest
        );
        let other = json!({"GovernanceVote": {"proposal_id": "p", "vote": false}});
        assert!(
            check_signing_payload(&e, &other, &payload).is_err(),
            "a different vote is refused"
        );
    }
}
