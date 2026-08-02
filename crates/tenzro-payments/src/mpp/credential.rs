//! MPP Credential types (payment proof)
//!
//! Implements IETF `draft-ryan-httpauth-payment-01` credential shape with two
//! Tenzro-native extension fields, both stored under `extensions`:
//!
//! - `mandate` — TDIP delegation scope (max_transaction_value, allowed_operations,
//!   time_bound, controller_did, signature) carried inline so a single Payment
//!   credential proves payment-auth AND agent-mandate atomically.
//! - `settlement_proof` — `{ tx_hash, zk_commitment, circuit_id }` referencing
//!   a Plonky3 settlement-AIR proof recorded on the Tenzro ledger.
//!
//! Custom lowercase params are explicitly permitted by the draft (§3 "auth-params").

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An MPP payment credential that proves payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppCredential {
    /// Credential ID
    pub credential_id: String,
    /// Challenge this responds to
    pub challenge_id: String,
    /// Payer DID
    pub payer_did: String,
    /// Payer wallet address
    pub payer_address: String,
    /// Payment amount
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Settlement chain
    pub chain: String,
    /// Signature over the credential data
    pub signature: Vec<u8>,
    /// Timestamp
    pub created_at: DateTime<Utc>,
    /// Additional fields
    pub extensions: HashMap<String, serde_json::Value>,
}

impl MppCredential {
    /// Creates a new MPP credential
    pub fn new(
        challenge_id: impl Into<String>,
        payer_did: impl Into<String>,
        payer_address: impl Into<String>,
        amount: u128,
        asset: impl Into<String>,
    ) -> Self {
        Self {
            credential_id: uuid::Uuid::new_v4().to_string(),
            challenge_id: challenge_id.into(),
            payer_did: payer_did.into(),
            payer_address: payer_address.into(),
            amount,
            asset: asset.into(),
            chain: "tempo".to_string(),
            signature: Vec::new(),
            created_at: Utc::now(),
            extensions: HashMap::new(),
        }
    }

    /// Attaches a TDIP delegation mandate to the credential's `mandate` extension.
    ///
    /// The mandate proves the agent is acting within delegated scope. Verifiers
    /// resolve `controller_did` via `IdentityRegistry` and check delegation
    /// scope + runtime spending policy alongside the payment proof.
    pub fn with_mandate(mut self, mandate: TenzroMandateExtension) -> Self {
        self.extensions.insert(
            "mandate".to_string(),
            serde_json::to_value(mandate).unwrap_or(serde_json::Value::Null),
        );
        self
    }

    /// Attaches a Plonky3 settlement-proof reference to the credential's
    /// `settlement_proof` extension.
    pub fn with_settlement_proof(mut self, proof: TenzroSettlementProof) -> Self {
        self.extensions.insert(
            "settlement_proof".to_string(),
            serde_json::to_value(proof).unwrap_or(serde_json::Value::Null),
        );
        self
    }

    /// Returns the embedded TDIP mandate, if any.
    pub fn mandate(&self) -> Option<TenzroMandateExtension> {
        self.extensions
            .get("mandate")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Returns the embedded Plonky3 settlement proof reference, if any.
    pub fn settlement_proof(&self) -> Option<TenzroSettlementProof> {
        self.extensions
            .get("settlement_proof")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Serializes this credential into the IETF `Authorization: Payment <base64url>`
    /// header value (without the `Authorization: ` prefix).
    ///
    /// Body shape per `draft-ryan-httpauth-payment-01`:
    /// ```text
    /// {
    ///   "challenge": { "id": ..., ...echoed challenge params... },
    ///   "source":    "did:tenzro:machine:...",
    ///   "payload":   { ...method-specific proof... }
    /// }
    /// ```
    /// The Tenzro `mandate` and `settlement_proof` are top-level siblings
    /// to `payload`, in the lowercase-named custom-params namespace allowed by §3.
    pub fn to_ietf_payment_header(&self) -> Result<String, serde_json::Error> {
        use base64::{Engine as _, engine::general_purpose};
        let body = IetfPaymentBody::from(self);
        let json = serde_json::to_vec(&body)?;
        Ok(format!(
            "Payment {}",
            general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }
}

/// IETF `draft-ryan-httpauth-payment-01` credential body.
///
/// Wire shape returned by `MppCredential::to_ietf_payment_header()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IetfPaymentBody {
    /// Echoed challenge params (id, realm, method, intent, ...).
    pub challenge: serde_json::Value,
    /// Payer identifier — DID format per [W3C-DID] is RECOMMENDED by the draft.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    /// Method-specific proof (signature, settlement-tx, ...).
    pub payload: serde_json::Value,
    /// Tenzro extension: TDIP delegation scope.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mandate: Option<TenzroMandateExtension>,
    /// Tenzro extension: Plonky3 settlement-proof reference.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub settlement_proof: Option<TenzroSettlementProof>,
}

impl From<&MppCredential> for IetfPaymentBody {
    fn from(c: &MppCredential) -> Self {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "credential_id".to_string(),
            serde_json::Value::String(c.credential_id.clone()),
        );
        payload.insert(
            "amount".to_string(),
            serde_json::Value::String(c.amount.to_string()),
        );
        payload.insert(
            "asset".to_string(),
            serde_json::Value::String(c.asset.clone()),
        );
        payload.insert(
            "chain".to_string(),
            serde_json::Value::String(c.chain.clone()),
        );
        payload.insert(
            "payer_address".to_string(),
            serde_json::Value::String(c.payer_address.clone()),
        );
        payload.insert(
            "signature".to_string(),
            serde_json::Value::String({
                use base64::{Engine as _, engine::general_purpose};
                general_purpose::URL_SAFE_NO_PAD.encode(&c.signature)
            }),
        );
        payload.insert(
            "created_at".to_string(),
            serde_json::Value::String(c.created_at.to_rfc3339()),
        );
        let mut challenge = serde_json::Map::new();
        challenge.insert(
            "id".to_string(),
            serde_json::Value::String(c.challenge_id.clone()),
        );
        Self {
            challenge: serde_json::Value::Object(challenge),
            source: c.payer_did.clone(),
            payload: serde_json::Value::Object(payload),
            mandate: c.mandate(),
            settlement_proof: c.settlement_proof(),
        }
    }
}

/// Tenzro extension: TDIP delegation mandate carried inline in an MPP credential.
///
/// One header proves payment-auth + agent-mandate atomically. Verifier resolves
/// `controller_did` via `IdentityRegistry::resolve_identity()` and checks
/// `enforce_operation()` against `max_transaction_value` / `allowed_operations` /
/// `time_bound` claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenzroMandateExtension {
    /// `did:tenzro:human:*` or `did:tenzro:machine:*` of the controller.
    pub controller_did: String,
    /// Maximum value per transaction in the credential's `asset` units.
    pub max_transaction_value: u128,
    /// Operations the agent is delegated to perform (e.g., "payment", "swap").
    pub allowed_operations: Vec<String>,
    /// Mandate validity window. Verifier rejects if outside.
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// Ed25519 signature over the canonical encoding of this mandate by `controller_did`.
    /// Signature preimage:
    ///   "tenzro/mpp/mandate" || controller_did || max_transaction_value(LE) ||
    ///   sorted(allowed_operations) || valid_from(unix_le) || valid_until(unix_le)
    pub signature: Vec<u8>,
}

/// Tenzro extension: reference to a Plonky3 settlement-AIR proof anchored on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenzroSettlementProof {
    /// Block height where the settlement-AIR commitment was registered.
    pub block_height: u64,
    /// Settlement transaction hash on the Tenzro ledger.
    pub tx_hash: String,
    /// 32-byte SHA-256 commitment of the Plonky3 proof envelope, as recorded
    /// in `ZkCommitmentRegistry`. Hex-encoded.
    pub zk_commitment: String,
    /// Always `"settlement"` for this extension.
    pub circuit_id: String,
}
