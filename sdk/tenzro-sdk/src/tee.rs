//! TEE (Trusted Execution Environment) SDK for Tenzro Network
//!
//! This module provides TEE hardware detection, remote attestation, and
//! enclave data sealing/unsealing across Intel TDX, AMD SEV-SNP, AWS Nitro,
//! and NVIDIA GPU Confidential Computing.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Client for Trusted Execution Environment operations
///
/// Supports Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU TEE providers.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let tee = client.tee();
///
/// // Detect available TEE hardware
/// let info = tee.detect_tee().await?;
/// println!("TEE available: {} ({:?})", info.available, info.vendor);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TeeClient {
    rpc: Arc<RpcClient>,
}

impl TeeClient {
    /// Creates a new TEE client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Detects available TEE hardware on the node
    ///
    /// Returns information about the TEE vendor and capabilities.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let tee = client.tee();
    /// let info = tee.detect_tee().await?;
    /// if info.available {
    ///     println!("TEE vendor: {:?}", info.vendor);
    ///     println!("Vendors: {:?}", info.available_vendors);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect_tee(&self) -> SdkResult<TeeInfo> {
        self.rpc
            .call("tenzro_detectTee", serde_json::json!([]))
            .await
    }

    /// Generates a TEE attestation report
    ///
    /// # Arguments
    ///
    /// * `user_data` - Optional hex data the report commits to (64 zero bytes
    ///   when omitted)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let tee = client.tee();
    /// let attestation = tee.get_attestation(None).await?;
    /// for m in &attestation.measurements {
    ///     println!("{} {}", m.register, m.value_hex);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_attestation(&self, user_data: Option<&str>) -> SdkResult<AttestationResult> {
        let mut params = serde_json::json!({});
        if let Some(d) = user_data {
            params["user_data"] = serde_json::Value::from(d);
        }
        self.rpc.call("tenzro_getTeeAttestation", params).await
    }

    /// Requests a single-use nonce for one attestation verification.
    ///
    /// The attester asks its TEE for a report over `nonce || bound_data` and
    /// submits it with [`TeeClient::verify_attestation`] within the nonce's
    /// lifetime (`expires_in_secs`).
    pub async fn attestation_challenge(&self) -> SdkResult<AttestationChallenge> {
        self.rpc
            .call("tenzro_teeAttestationChallenge", serde_json::json!({}))
            .await
    }

    /// Verifies a TEE attestation report against a nonce this node issued.
    ///
    /// The report must be signed by the vendor, chain to a pinned vendor
    /// root, and carry `nonce || bound_data` (packed for its vendor) as its
    /// hardware-signed user data. The nonce is consumed.
    ///
    /// # Arguments
    ///
    /// * `report_hex` - Hex of the JSON `AttestationReport`
    /// * `nonce` - Hex nonce from [`TeeClient::attestation_challenge`]
    /// * `bound_data` - Optional hex of extra data the report commits to
    /// * `facility` - Optional signed facility claim (JSON)
    pub async fn verify_attestation(
        &self,
        report_hex: &str,
        nonce: &str,
        bound_data: Option<&str>,
        facility: Option<serde_json::Value>,
    ) -> SdkResult<TeeVerifyResult> {
        let mut params = serde_json::json!({
            "report_hex": report_hex,
            "nonce": nonce,
        });
        if let Some(b) = bound_data {
            params["bound_data"] = serde_json::Value::from(b);
        }
        if let Some(f) = facility {
            params["facility"] = f;
        }
        self.rpc.call("tenzro_verifyTeeAttestation", params).await
    }

    /// Lists available TEE providers on the network
    ///
    /// Returns providers with their vendor type and availability status.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let tee = client.tee();
    /// let list = tee.list_tee_providers().await?;
    /// for p in &list.providers {
    ///     println!("{}: {}", p.id, p.info);
    /// }
    /// println!("local TEE: {:?}", list.local_vendor);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_tee_providers(&self) -> SdkResult<TeeProviderList> {
        self.rpc
            .call("tenzro_listTeeProviders", serde_json::json!([]))
            .await
    }
}

/// TEE hardware information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeInfo {
    /// Whether TEE hardware is available
    pub available: bool,
    /// The vendor detected on this node, when one is (`IntelTdx`, `AmdSevSnp`, ...)
    #[serde(default)]
    pub vendor: Option<String>,
    /// Every vendor this node can attest with
    #[serde(default)]
    pub available_vendors: Vec<String>,
}

/// TEE attestation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Vendor of the report
    pub vendor: String,
    /// Hex report data the hardware signed
    pub user_data_hex: String,
    /// Hex launch measurement (TDX MRTD, SEV-SNP MEASUREMENT)
    pub measurement_hex: String,
    /// Every measurement register the evidence carries
    #[serde(default)]
    pub measurements: Vec<MeasurementRegister>,
    /// Hex of the JSON report, as `verify_attestation` takes it
    pub report_hex: String,
    /// Milliseconds since the epoch the report was made at
    pub timestamp: u64,
}

/// One measurement register of a report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementRegister {
    /// Register name (`MRTD`, `RTMR0`..`RTMR3`, `MEASUREMENT`, `PCR0`..)
    pub register: String,
    /// Hash algorithm
    pub algorithm: String,
    /// Hex register value
    pub value_hex: String,
}

/// TEE attestation verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeVerifyResult {
    /// Whether the attestation is valid
    pub valid: bool,
    /// Why it is not, when `valid` is false
    pub error: Option<String>,
    /// Vendor of the verified report
    pub vendor: Option<String>,
    /// Hex launch measurement of the verified report
    pub measurement_hex: Option<String>,
    /// Hex per-platform identifier of the verified report
    pub platform_id_hex: Option<String>,
    /// The vendor's TCB verdict
    pub tcb_status: Option<String>,
    /// The facility the report was bound to, if a claim was presented
    pub facility: Option<String>,
    /// Every measurement register of the verified report
    #[serde(default)]
    pub measurements: Vec<MeasurementRegister>,
}

/// A single-use nonce for one attestation verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChallenge {
    /// Hex nonce, `0x`-prefixed
    pub nonce: String,
    /// Seconds the nonce stays redeemable
    pub expires_in_secs: u64,
}

/// A TEE provider registered on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeProvider {
    /// Registry id (`tee:<address>`).
    pub id: String,
    /// The provider's stored record (vendor, capabilities, endpoint).
    pub info: serde_json::Value,
}

/// Result of `tenzro_listTeeProviders`: registered providers and this node's
/// own TEE detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeProviderList {
    /// TEE providers registered on the network.
    #[serde(default)]
    pub providers: Vec<TeeProvider>,
    /// Number of registered providers.
    #[serde(default)]
    pub total: u64,
    /// Whether this node detected TEE hardware.
    #[serde(default)]
    pub local_tee_available: bool,
    /// The vendor this node detected, when it did.
    #[serde(default)]
    pub local_vendor: Option<String>,
}

impl TeeClient {
    /// Calls `tenzro_getZkAttestation`: get zk attestation.
    pub async fn get_zk_attestation(
        &self,
        commitment: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getZkAttestation",
                serde_json::json!({ "commitment": commitment }),
            )
            .await
    }
}
