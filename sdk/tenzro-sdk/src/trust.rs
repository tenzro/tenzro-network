//! Certifications, ratings, operator policies and model
//! provenance.
//!
//! Every record is signed by its author on their own TPM, Secure Enclave or
//! passkey before it reaches this client; the node verifies each one, so
//! submitting a record grants it nothing it cannot prove. Records are JSON
//! documents (W3C Verifiable Credential 2.0 shapes with an `ecdsa-jcs-2019`
//! proof) and are passed through unchanged.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde_json::{Value, json};
use std::sync::Arc;

/// Trust ledger client.
pub struct TrustClient {
    rpc: Arc<RpcClient>,
}

impl TrustClient {
    /// Creates a new trust client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Submits a signed credential, revocation, issuer revocation, trust
    /// list, operator policy, origin attestation, model manifest or policy
    /// violation evidence. A violation proven for the first time slashes the
    /// operator's compute bond; the result reports it.
    pub async fn submit(&self, record: &Value) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_submitTrustRecord", json!({ "record": record }))
            .await
    }

    /// Verifies a credential: its proof, validity window, the issuer's
    /// status list and whether the issuer's key was revoked.
    pub async fn verify_credential(&self, credential: &Value) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_verifyTrustCredential",
                json!({ "credential": credential }),
            )
            .await
    }

    /// Credentials about a subject: `tenzro:model:<root>`, an operator DID,
    /// or a model name with a verified manifest.
    pub async fn credentials(&self, subject: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getTrustCredentials", json!({ "subject": subject }))
            .await
    }

    /// An issuer's Bitstring Status List and the revocations it was built from.
    pub async fn status_list(&self, issuer: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getStatusList", json!({ "issuer": issuer }))
            .await
    }

    /// An operator's policy in force, its history and proven violations.
    pub async fn operator_policy(&self, operator: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getOperatorPolicy", json!({ "operator": operator }))
            .await
    }

    /// A model's manifests, origin observations and verification status, by
    /// manifest root or by name.
    pub async fn model_provenance(&self, root_or_name: &str) -> SdkResult<Value> {
        let is_root =
            root_or_name.len() == 64 && root_or_name.bytes().all(|b| b.is_ascii_hexdigit());
        let params = if is_root {
            json!({ "root": root_or_name })
        } else {
            json!({ "name": root_or_name })
        };
        self.rpc.call("tenzro_getModelProvenance", params).await
    }
}

impl TrustClient {
    /// Calls `tenzro_hostModel`: host model.
    pub async fn host_model(
        &self,
        name: Option<&str>,
        root: Option<&str>,
        path: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_hostModel",
                serde_json::json!({ "name": name, "root": root, "path": path }),
            )
            .await
    }

    /// Calls `tenzro_scanModelFiles`: scan model files.
    pub async fn scan_model_files(
        &self,
        name: Option<&str>,
        root: Option<&str>,
        path: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_scanModelFiles",
                serde_json::json!({ "name": name, "root": root, "path": path }),
            )
            .await
    }

    /// Calls `tenzro_verifyModelFiles`: verify model files.
    pub async fn verify_model_files(
        &self,
        name: Option<&str>,
        root: Option<&str>,
        path: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyModelFiles",
                serde_json::json!({ "name": name, "root": root, "path": path }),
            )
            .await
    }

    /// Publish the measurement of an attestation `report` answering the
    /// challenge `nonce` (hex). The publisher's hardware `signer` signs
    /// [`tee_publication_statement`] with its P-256 key.
    pub async fn publish_tee_measurement(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        report: Value,
        nonce: &str,
        measurement: &[u8],
    ) -> SdkResult<Value> {
        let vendor = report
            .get("vendor")
            .and_then(Value::as_str)
            .and_then(tee_vendor_label)
            .ok_or_else(|| {
                crate::error::SdkError::InvalidParameter(
                    "the report names no known TEE vendor".into(),
                )
            })?;
        let statement = tee_publication_statement(vendor, measurement);
        let signature = signer.sign_p256(&statement).await?;
        self.rpc
            .call(
                "tenzro_publishTeeMeasurement",
                json!({
                    "report": report,
                    "nonce": nonce.trim_start_matches("0x"),
                    "publisher_key_hex": hex::encode(crate::wallet::p256_sec1(&signer.p256_public_key())),
                    "signature_hex": hex::encode(signature),
                }),
            )
            .await
    }
}

/// The label a TEE vendor's measurement publication commits to, from the
/// vendor's wire name in an attestation report.
pub fn tee_vendor_label(wire: &str) -> Option<&'static str> {
    Some(match wire {
        "IntelSGX" => "Intel SGX",
        "IntelTdx" => "Intel TDX",
        "AMDSEV" => "AMD SEV",
        "AmdSevSnp" => "AMD SEV-SNP",
        "ARMTrustZone" => "ARM TrustZone",
        "AWSNitro" | "AwsNitro" => "AWS Nitro",
        "NvidiaGpu" => "NVIDIA GPU CC",
        "Generic" => "Generic",
        _ => return None,
    })
}

/// The statement a measurement publisher signs, identical to
/// `tenzro_types::tee::publication_statement`.
pub fn tee_publication_statement(vendor_label: &str, measurement: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/attestation-log/publish\0");
    h.update(vendor_label.as_bytes());
    h.update((measurement.len() as u32).to_be_bytes());
    h.update(measurement);
    h.finalize().into()
}
