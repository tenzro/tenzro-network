//! Node access: sign in for a DPoP-bound access token, and administer who
//! may use a node.
//!
//! A caller proves who it is once, with a passkey or a hardware key, and
//! receives a short-lived ES256 access token bound to its DPoP key. Every
//! later request carries the token and a fresh DPoP proof; the node
//! re-evaluates its access policy for the token's DID on each one.
//!
//! The policy and token methods are for the node's operator and the
//! administrators its policy names; the node refuses anyone else.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::SdkResult;
use crate::rpc::RpcClient;

/// Mints DPoP proofs (RFC 9449) with a key the caller holds in hardware.
pub trait DpopProver: Send + Sync {
    /// RFC 7638 thumbprint of the DPoP public key.
    fn jkt(&self) -> SdkResult<String>;
    /// A proof for one request: `htm` and `htu` of the request, and the
    /// access token it accompanies (hashed into `ath`).
    fn proof(&self, htm: &str, htu: &str, access_token: &str) -> SdkResult<String>;
}

/// An access token and the DPoP key it is bound to.
#[derive(Clone)]
pub struct AccessCredential {
    /// The ES256 access token.
    pub token: String,
    /// The key the token is bound to.
    pub prover: Arc<dyn DpopProver>,
}

impl std::fmt::Debug for AccessCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessCredential").finish_non_exhaustive()
    }
}

/// A sign-in challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessChallenge {
    /// Answer with this id.
    pub challenge_id: String,
    /// The challenge a passkey signs (`webauthn.get`), base64url.
    pub challenge: String,
    /// The digest a hardware key signs, hex.
    pub device_digest: String,
    /// Seconds the challenge stays answerable.
    pub expires_in: u64,
}

/// The answer to a sign-in challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignInProof {
    /// A passkey assertion over `challenge`, fields base64url.
    Passkey {
        /// The smart account the passkey is enrolled on, hex.
        account_address: String,
        /// The credential id.
        credential_id: String,
        /// Authenticator data.
        authenticator_data: String,
        /// Client data JSON.
        client_data_json: String,
        /// The assertion signature.
        signature: String,
    },
    /// A hardware-key signature over `device_digest`, fields hex.
    Device {
        /// The key the DID derives from, or one registered on it.
        public_key: String,
        /// ECDSA P-256 `r || s` over SHA-256 of the digest, or Ed25519.
        signature: String,
    },
}

/// An issued access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedAccessToken {
    /// The ES256 access token.
    pub access_token: String,
    /// Always `DPoP`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// The DID signed in.
    pub did: String,
    /// The method classes the policy admits the DID to.
    pub classes: Vec<String>,
    /// The node's token-signing key.
    pub jwk: Value,
}

/// Node access RPCs.
#[derive(Clone)]
pub struct AccessClient {
    rpc: Arc<RpcClient>,
}

impl AccessClient {
    /// Creates a new access client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// `tenzro_accessChallenge`: a single-use challenge for `did`, bound to
    /// the DPoP key `dpop_jkt`.
    pub async fn challenge(&self, did: &str, dpop_jkt: &str) -> SdkResult<AccessChallenge> {
        self.rpc
            .call(
                "tenzro_accessChallenge",
                json!({ "did": did, "dpop_jkt": dpop_jkt }),
            )
            .await
    }

    /// `tenzro_issueAccessToken`: answer a challenge. `credentials` are KYA
    /// credentials about the DID, for policies that require one.
    pub async fn issue(
        &self,
        challenge_id: &str,
        proof: &SignInProof,
        credentials: Option<Vec<Value>>,
    ) -> SdkResult<IssuedAccessToken> {
        let mut params = json!({ "challenge_id": challenge_id, "proof": proof });
        if let Some(c) = credentials {
            params["credentials"] = Value::Array(c);
        }
        self.rpc.call("tenzro_issueAccessToken", params).await
    }

    /// `tenzro_getAccessPolicy`: the policy in force, as data and as TOML.
    pub async fn get_policy(&self) -> SdkResult<Value> {
        self.rpc.call("tenzro_getAccessPolicy", json!({})).await
    }

    /// `tenzro_setAccessPolicy`: replace the policy with `toml`. Returns the
    /// new version.
    pub async fn set_policy(&self, toml: &str) -> SdkResult<u64> {
        let v: Value = self
            .rpc
            .call("tenzro_setAccessPolicy", json!({ "toml": toml }))
            .await?;
        Ok(v["version"].as_u64().unwrap_or_default())
    }

    /// `tenzro_previewAccess`: what the policy decides for `did` (anonymous
    /// when `None`) calling `method` on `surface`.
    pub async fn preview(
        &self,
        surface: &str,
        method: &str,
        did: Option<&str>,
    ) -> SdkResult<Value> {
        let mut params = json!({ "surface": surface, "method": method });
        if let Some(d) = did {
            params["did"] = json!(d);
        }
        self.rpc.call("tenzro_previewAccess", params).await
    }

    /// `tenzro_listAccessTokens`: the live tokens the node issued.
    pub async fn list_tokens(&self) -> SdkResult<Value> {
        self.rpc.call("tenzro_listAccessTokens", json!({})).await
    }

    /// `tenzro_revokeAccessToken`: withdraw one token by `jti`.
    pub async fn revoke_token(&self, jti: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_revokeAccessToken", json!({ "jti": jti }))
            .await
    }

    /// `tenzro_revokeAccessToken`: withdraw every live token of `did`.
    pub async fn revoke_did(&self, did: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_revokeAccessToken", json!({ "did": did }))
            .await
    }

    /// `tenzro_listAdminAudit`: the node's administrative audit log, the
    /// most recent records `filter` selects, oldest first.
    pub async fn audit_log(&self, filter: &AuditFilter) -> SdkResult<AuditLog> {
        self.rpc
            .call("tenzro_listAdminAudit", serde_json::to_value(filter)?)
            .await
    }

    /// `tenzro_verifyAdminAudit`: check the audit log's chain, its signed
    /// checkpoints under this node's identity key, and that the log ends where
    /// the node last wrote.
    pub async fn verify_audit_log(&self) -> SdkResult<AuditVerification> {
        self.rpc.call("tenzro_verifyAdminAudit", json!({})).await
    }
}

/// Which audit records `tenzro_listAdminAudit` returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Only records about this method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Only records whose principal is this DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// From this time, inclusive: RFC 3339 or Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<Value>,
    /// Before this time: RFC 3339 or Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<Value>,
    /// Most records, the most recent; 100 when unset, at most 1000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// `tenzro_listAdminAudit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Records returned.
    pub count: u64,
    /// The records, oldest first, each with the hash it is chained by.
    pub records: Vec<AuditLine>,
}

/// One line of the audit log: a record and its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLine {
    /// The record.
    pub record: AuditRecord,
    /// SHA-256 over the domain and the record's JSON, hex.
    pub hash: String,
}

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Position in the chain, from 0.
    pub seq: u64,
    /// Hash of the record before it.
    pub prev: String,
    /// When, RFC 3339 UTC with milliseconds.
    pub at: String,
    /// The node's machine DID, when its identity key was open.
    pub node: Option<String>,
    /// The chain id.
    pub chain_id: u64,
    /// What happened: `kind` (`call`, `completion`, `sign_in`, `checkpoint`
    /// or `opened`) and its `data`.
    pub entry: AuditEntry,
}

/// The entry of an audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// `call`, `completion`, `sign_in`, `checkpoint` or `opened`.
    pub kind: String,
    /// The entry's fields.
    pub data: Value,
}

/// `tenzro_verifyAdminAudit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerification {
    /// True when the chain is whole, every checkpoint verifies and the log
    /// ends where the node last wrote.
    pub ok: bool,
    /// Records read.
    pub records: u64,
    /// Segments read, oldest first.
    pub segments: Vec<String>,
    /// First sequence number read.
    pub first_seq: Option<u64>,
    /// Last sequence number read.
    pub last_seq: Option<u64>,
    /// Hash of the last record read.
    pub head_hash: Option<String>,
    /// Checkpoints read.
    pub checkpoints: u64,
    /// Checkpoints whose signature verified under the node's identity key.
    pub signed_checkpoints: u64,
    /// Checkpoints written without a signature.
    pub unsigned_checkpoints: u64,
    /// Everything that is wrong, one sentence each.
    pub problems: Vec<String>,
}
