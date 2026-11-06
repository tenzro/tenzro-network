//! Permit2 `SignatureTransfer` client.
//!
//! Wraps the node's Permit2 surface on the Tenzro EVM. Permit2 lets users
//! sign a single EIP-712 message authorizing a token transfer (with an
//! optional witness binding the permit to an off-chain artifact). The domain separator and the digest a user
//! signs are computed offline by the signer.
//!
//! - `tenzro_permit2VerifyAndConsume` — atomic verify + nonce-consume
//!   for a relayer presenting a signed permit.
//! - `tenzro_permit2NonceUsed` — read whether a `(owner, nonce)` slot
//!   has been consumed.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct Permit2Client {
    rpc: Arc<RpcClient>,
}

impl Permit2Client {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Atomically verify a signed Permit2 message and consume its
    /// `(owner, nonce)` slot. Returns the consumed nonce position.
    pub async fn verify_and_consume(
        &self,
        req: Permit2VerifyAndConsumeRequest,
    ) -> SdkResult<Permit2VerifyAndConsumeResult> {
        self.rpc
            .call("tenzro_permit2VerifyAndConsume", serde_json::json!([req]))
            .await
    }

    /// Check whether a `(owner, nonce)` slot has been consumed.
    pub async fn nonce_used(&self, owner: &str, nonce: &str) -> SdkResult<Permit2NonceUsed> {
        self.rpc
            .call(
                "tenzro_permit2NonceUsed",
                serde_json::json!([{ "owner": owner, "nonce": nonce }]),
            )
            .await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Permit2VerifyAndConsumeRequest {
    pub chain_id: u64,
    pub owner: String,
    pub token: String,
    pub amount: String,
    pub spender: String,
    pub nonce: String,
    pub deadline: u64,
    pub signature: String,
    /// The witness, 32 bytes hex, for a witness transfer. With
    /// `witness_type_name` and `witness_type_string`; the node checks the
    /// signature over the witness digest only when all three are given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<String>,
    /// The witness struct's type name, as in the EIP-712 type string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_type_name: Option<String>,
    /// The witness type string the permit was signed with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_type_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit2VerifyAndConsumeResult {
    #[serde(default)]
    pub consumed: bool,
    #[serde(default)]
    pub word_pos: String,
    #[serde(default)]
    pub bit_pos: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit2NonceUsed {
    #[serde(default)]
    pub used: bool,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub nonce: String,
}
