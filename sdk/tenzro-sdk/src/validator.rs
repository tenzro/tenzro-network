//! Validator registry client for Tenzro Network
//!
//! Wraps the `tenzro_getValidatorState` / `tenzro_listValidators` /
//! `tenzro_listActiveValidators` RPCs. Used by operator dashboards, SREs,
//! validator-fleet tooling, and any consumer that needs to enumerate the
//! active set or inspect a single validator's stake / activation epoch /
//! TEE-attestation status.
//!
//! Validator registration happens through the staking transaction path.
//! A validator's consensus keys are session keys certified by its hardware
//! key each boot and epoch, so there is no key-rotation call.
//!
//! # Example
//!
//! ```no_run
//! # use tenzro_sdk::TenzroClient;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//! let actives = client.validators().list_active().await?;
//! println!("{} active validators", actives.count);
//! for v in actives.validators {
//!     println!("{}: stake={}", v.address, v.self_stake);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Validator registry status, mirrored to its Rust `Debug`-format
/// string on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Candidate,
    PendingActive,
    PendingExit,
    Exited,
    Jailed,
}

/// A single entry in the on-chain validator registry.
///
/// `address` and `withdrawal_address` are base58-encoded (Tenzro's
/// `Address::Display` impl). Pubkeys are plain lowercase hex without
/// `0x` prefix. `self_stake` is a u128 encoded as a decimal string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistryEntry {
    /// Base58-encoded 32-byte address.
    #[serde(default)]
    pub address: String,
    /// Hardware validator key, ML-DSA-65 leg (1952 bytes), hex-encoded.
    #[serde(default)]
    pub ml_dsa_pubkey: String,
    /// Hardware validator key, P-256 leg, hex-encoded.
    #[serde(default)]
    pub p256_pubkey: String,
    /// The node's Ed25519 network key (32 bytes), hex-encoded.
    #[serde(default)]
    pub node_key: String,
    /// Base58-encoded 32-byte withdrawal address.
    #[serde(default)]
    pub withdrawal_address: String,
    /// u128 decimal string.
    #[serde(default)]
    pub self_stake: String,
    pub status: ValidatorStatus,
    #[serde(default)]
    pub registered_at_epoch: u64,
    #[serde(default)]
    pub activated_at_epoch: Option<u64>,
    #[serde(default)]
    pub exited_at_epoch: Option<u64>,
    #[serde(default)]
    pub jailed_until_epoch: Option<u64>,
    #[serde(default)]
    pub tee_attestation_hash: Option<String>,
    #[serde(default)]
    pub metadata_uri: String,
    /// Unix ms timestamp of last registry mutation.
    #[serde(default)]
    pub updated_at: u64,
}

/// Result of `tenzro_listValidators` / `tenzro_listActiveValidators`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListValidatorsResult {
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub validators: Vec<ValidatorRegistryEntry>,
}

/// Read-only validator registry client.
#[derive(Clone)]
pub struct ValidatorClient {
    rpc: Arc<RpcClient>,
}

impl ValidatorClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Fetch a single validator's entry by hex-encoded 32-byte address
    /// (with or without `0x` prefix). Returns `None` if not registered.
    pub async fn get_state(&self, address: &str) -> SdkResult<Option<ValidatorRegistryEntry>> {
        self.rpc
            .call(
                "tenzro_getValidatorState",
                serde_json::json!({ "address": address }),
            )
            .await
    }

    /// List validators, optionally filtered by status.
    pub async fn list(&self, status: Option<ValidatorStatus>) -> SdkResult<ListValidatorsResult> {
        let params = match status {
            Some(s) => serde_json::json!({ "status": s }),
            None => serde_json::json!({}),
        };
        self.rpc.call("tenzro_listValidators", params).await
    }

    /// List only currently-Active validators. Convenience over
    /// `list(Some(ValidatorStatus::Active))`.
    pub async fn list_active(&self) -> SdkResult<ListValidatorsResult> {
        self.rpc
            .call("tenzro_listActiveValidators", serde_json::json!({}))
            .await
    }
}
