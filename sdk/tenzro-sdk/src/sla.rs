//! SLA fault-detector inspection client for Tenzro Network
//!
//! Wraps the validator-side SLA RPCs:
//!
//! - `tenzro_slaIssueProbe` — issue a VRF-bound liveness probe to a
//!   ModelProvider / TeeProvider DID and broadcast it on the
//!   `tenzro/sla` gossipsub topic. Validator-only — non-validator
//!   nodes return `-32000 SlaManager not initialized`.
//! - `tenzro_slaListOutstandingProbes` — list every in-flight probe
//!   awaiting a response, regardless of who issued it. Used by
//!   operators to spot stuck probes whose deadline has already
//!   elapsed without a response.
//! - `tenzro_slaGetParams` — the penalty a frozen unavailable verdict
//!   takes from a compute bond (`unavailable_penalty_wei`) and this
//!   validator's VRF public key.
//!
//! Probes are addressed by their 32-byte `challenge_nonce` (hex-encoded
//! with a `0x` prefix on the wire).
//!
//! # Example
//!
//! ```no_run
//! # use tenzro_sdk::TenzroClient;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//! let sla = client.sla();
//!
//! let params = sla.get_params().await?;
//! println!("unavailable_penalty_wei={}", params.unavailable_penalty_wei);
//!
//! let outstanding = sla.list_outstanding_probes().await?;
//! println!("{} in-flight probes", outstanding.count);
//! # Ok(())
//! # }
//! ```

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Validator-side SLA fault-detector inspection client.
#[derive(Clone)]
pub struct SlaClient {
    rpc: Arc<RpcClient>,
}

impl SlaClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Issue a VRF-bound liveness probe to `provider_did`.
    ///
    /// Validator-only. The issuing node:
    /// 1. Computes the VRF output over `(provider_did, epoch, round)`.
    /// 2. Registers the probe in its in-memory outstanding-probe map
    ///    (so a fast response cannot race the insertion).
    /// 3. Broadcasts the probe on the `tenzro/sla` gossipsub topic.
    ///
    /// `deadline_ms` is a Unix millisecond timestamp by which the
    /// provider must respond before the probe is considered missed.
    pub async fn issue_probe(
        &self,
        provider_did: &str,
        epoch: u64,
        round: u64,
        deadline_ms: i64,
    ) -> SdkResult<SlaProbeIssued> {
        self.rpc
            .call(
                "tenzro_slaIssueProbe",
                serde_json::json!([{
                    "provider_did": provider_did,
                    "epoch": epoch,
                    "round": round,
                    "deadline_ms": deadline_ms,
                }]),
            )
            .await
    }

    /// List every in-flight probe awaiting a response from any
    /// provider, regardless of issuer. Used by operators to spot
    /// probes whose `deadline_ms` has already elapsed without a
    /// matching response.
    pub async fn list_outstanding_probes(&self) -> SdkResult<SlaOutstandingProbes> {
        self.rpc
            .call("tenzro_slaListOutstandingProbes", serde_json::json!([]))
            .await
    }

    /// Read the fault-detector parameters this validator is using.
    /// Returns the slash threshold (missed probes before slashing
    /// fires), the per-crossing slash amount in wei, and this
    /// validator's VRF public key.
    pub async fn get_params(&self) -> SdkResult<SlaParams> {
        self.rpc
            .call("tenzro_slaGetParams", serde_json::json!([]))
            .await
    }
}

/// Probe issued by `tenzro_slaIssueProbe`. The `challenge_nonce` is
/// the 32-byte VRF output used to address the probe through its
/// lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaProbeIssued {
    /// 0x-prefixed hex of the issuing validator's address (32 bytes).
    #[serde(default)]
    pub issuer: String,
    /// DID of the provider being probed.
    #[serde(default)]
    pub provider_did: String,
    /// Validator epoch the probe was issued in.
    #[serde(default)]
    pub epoch: u64,
    /// Probe round within the epoch.
    #[serde(default)]
    pub round: u64,
    /// 0x-prefixed hex of the 32-byte VRF output addressing this probe.
    #[serde(default)]
    pub challenge_nonce: String,
    /// Unix-millisecond deadline by which the provider must respond.
    #[serde(default)]
    pub deadline_ms: i64,
    /// 0x-prefixed hex of the issuing validator's VRF public key.
    #[serde(default)]
    pub vrf_pubkey: String,
}

/// A single entry in the outstanding-probes reflector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaOutstandingProbe {
    #[serde(default)]
    pub challenge_nonce: String,
    #[serde(default)]
    pub provider_did: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub round: u64,
    #[serde(default)]
    pub deadline_ms: i64,
    /// 0x-prefixed hex of the issuing validator's address.
    #[serde(default)]
    pub issuer: String,
}

/// Result of `tenzro_slaListOutstandingProbes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaOutstandingProbes {
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub probes: Vec<SlaOutstandingProbe>,
}

/// Result of `tenzro_slaGetParams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaParams {
    /// What a frozen unavailable verdict takes from the provider's compute
    /// bond into the insurance pool, wei, as a decimal string.
    #[serde(default)]
    pub unavailable_penalty_wei: String,
    /// 0x-prefixed hex of this validator's VRF public key.
    #[serde(default)]
    pub vrf_pubkey: String,
}

impl SlaClient {
    /// Calls `tenzro_slaVerdict`: sla verdict.
    pub async fn sla_verdict(
        &self,
        provider_did: &str,
        epoch: u64,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_slaVerdict",
                serde_json::json!({ "provider_did": provider_did, "epoch": epoch }),
            )
            .await
    }
}
