//! Cryptographic Operations SDK for Tenzro Network
//!
//! Signing with the caller's bound wallet, signature verification and hashing
//! over RPC. Private keys never cross the wire: the node signs with the wallet
//! bound to the authenticated bearer.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Client for cryptographic operations
///
/// Provides signing with the caller's bound wallet, signature verification
/// and hashing. No operation sends or returns private key material.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let crypto = client.crypto();
///
/// // Verify a signature
/// # let signature = serde_json::json!({});
/// let result = crypto.verify_signature("04ab...", b"hello world", &signature).await?;
/// println!("Verified: {}", result.valid);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CryptoClient {
    rpc: Arc<RpcClient>,
}

impl CryptoClient {
    /// Creates a new crypto client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Verifies a composite signature over `message` against an account's
    /// P-256 public key (`tenzro_verifySignature`).
    ///
    /// `public_key` is the hex P-256 key and `signature` the composite
    /// signature in the network's JSON form (as
    /// [`crate::wallet::composite_signature_json`] builds it), made in the
    /// signed-message context. The node also checks the ML-DSA leg when the
    /// account has enrolled one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// # let signature = serde_json::json!({});
    /// let result = client.crypto().verify_signature("0x04ab...", b"hello", &signature).await?;
    /// println!("valid: {}, post-quantum leg: {}", result.valid, result.pq_leg_verified);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_signature(
        &self,
        public_key: &str,
        message: &[u8],
        signature: &serde_json::Value,
    ) -> SdkResult<VerifyResult> {
        self.rpc
            .call(
                "tenzro_verifySignature",
                serde_json::json!({
                    "public_key": public_key,
                    "message_hex": hex::encode(message),
                    "signature": signature,
                }),
            )
            .await
    }
}

/// Result of a signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// Whether the ML-DSA leg was present and verified.
    #[serde(default)]
    pub pq_leg_verified: bool,
    /// Whether the account has an ML-DSA key enrolled.
    #[serde(default)]
    pub pq_enrolled: bool,
}

/// Result of a VRF proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfVerifyResult {
    /// Whether the proof verifies.
    pub valid: bool,
    /// The VRF output, 0x-prefixed hex, when it does.
    #[serde(default)]
    pub output: Option<String>,
    /// Length of the output in bytes.
    #[serde(default)]
    pub output_len: Option<u64>,
    /// Why it does not.
    #[serde(default)]
    pub error: Option<String>,
}

impl CryptoClient {
    /// Verifies a VRF proof (`tenzro_verifyVrfProof`): `pubkey`, `proof` and
    /// the input `alpha` are hex.
    pub async fn verify_vrf_proof(
        &self,
        pubkey: &str,
        proof: &str,
        alpha: &str,
    ) -> crate::error::SdkResult<VrfVerifyResult> {
        self.rpc
            .call(
                "tenzro_verifyVrfProof",
                serde_json::json!({ "pubkey": pubkey, "proof": proof, "alpha": alpha }),
            )
            .await
    }
}
