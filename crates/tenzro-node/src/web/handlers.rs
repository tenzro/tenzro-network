use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::types::*;
use crate::event_loop::NodeEvent;
use crate::node::TenzroNode;
use tenzro_types::primitives::{BlockHeight, Timestamp};
use tenzro_types::tee::{AttestationReport, TeeVendor};
use tenzro_zk::{Proof, verify_proof_envelope};

/// Decode a JSON [`Proof`] envelope and run the STARK verifier on a blocking
/// thread. Anything that is not an envelope, or does not verify, is `false`.
async fn verify_zk_envelope_bytes(bytes: Vec<u8>) -> bool {
    let Ok(proof) = serde_json::from_slice::<Proof>(&bytes) else {
        return false;
    };
    tokio::task::spawn_blocking(move || verify_proof_envelope(&proof).is_ok())
        .await
        .unwrap_or(false)
}

/// Shared state for web handlers
pub struct WebState {
    pub node_version: String,
    /// Reference to the node for querying real status
    pub node: Option<Arc<TenzroNode>>,
    /// Event sender to submit transactions
    pub event_tx: Option<mpsc::Sender<NodeEvent>>,
    /// Metrics collector for Prometheus endpoint
    pub metrics: Option<crate::metrics::MetricsCollector>,
    /// Shared Prometheus registry for the network layer (gossip, dials, peer counts).
    /// When populated, `/metrics` will append the encoded `tenzro_network_*` metrics.
    pub network_metrics_registry: Option<Arc<Mutex<prometheus_client::registry::Registry>>>,
    /// Inference router for chat endpoint
    pub inference_router: Option<Arc<tenzro_model::InferenceRouter>>,
    /// Passkey credentials this node accepts assertions from.
    ///
    /// Replaces a stub that derived a credential verifying key from the
    /// credential *id* — a public identifier echoed in every assertion, so
    /// anyone who had seen one could reconstruct the signing half and mint
    /// assertions that verified. Hydrated from `CF_CREDENTIALS` once a node is
    /// attached, so a restart does not lock a wallet out of its own credential.
    pub passkey_registry: super::passkey_registry::PasskeyRegistry,
}

impl Default for WebState {
    fn default() -> Self {
        Self::new()
    }
}

impl WebState {
    pub fn new() -> Self {
        Self {
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            node: None,
            event_tx: None,
            metrics: None,
            network_metrics_registry: None,
            inference_router: None,
            passkey_registry: super::passkey_registry::PasskeyRegistry::new(),
        }
    }

    pub fn with_node(mut self, node: Arc<TenzroNode>) -> Self {
        // Hydrate registered passkeys from the node store. Without persistence
        // every wallet would be locked out of its share by a node restart, and
        // the tempting fix for that is to accept unregistered credentials —
        // which is exactly the hole this registry closes.
        if let Some(storage) = node.storage() {
            let kv: Arc<dyn tenzro_storage::kv::KvStore> = storage.clone();
            self.passkey_registry = super::passkey_registry::PasskeyRegistry::with_storage(kv);
        }
        self.node = Some(node);
        self
    }

    pub fn with_event_sender(mut self, tx: mpsc::Sender<NodeEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    pub fn with_metrics(mut self, metrics: crate::metrics::MetricsCollector) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Installs the shared Prometheus registry from the network layer.
    /// When set, `/metrics` will serialize the registered `tenzro_network_*`
    /// counters and gauges alongside the node-level metrics.
    pub fn with_network_metrics_registry(
        mut self,
        registry: Arc<Mutex<prometheus_client::registry::Registry>>,
    ) -> Self {
        self.network_metrics_registry = Some(registry);
        self
    }

    /// Wires the shared [`tenzro_model::InferenceRouter`] so the
    /// `/chat` endpoint can dispatch OpenAI-compatible chat-completion
    /// requests to the correct serving provider. Called from
    /// `main.rs` after the node's AI infrastructure is initialised.
    pub fn with_inference_router(mut self, router: Arc<tenzro_model::InferenceRouter>) -> Self {
        self.inference_router = Some(router);
        self
    }
}

/// Build the `did.json` URL for a `did:web` identifier.
/// `did:web:host` → `https://host/.well-known/did.json`;
/// `did:web:host:a:b` → `https://host/a/b/did.json`; `%3A` in the host decodes
/// to `:` (port).
fn did_web_url(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    let mut parts = rest.split(':');
    let host = parts.next()?.replace("%3A", ":").replace("%3a", ":");
    if host.is_empty() {
        return None;
    }
    let path: Vec<&str> = parts.collect();
    if path.is_empty() {
        Some(format!("https://{host}/.well-known/did.json"))
    } else {
        Some(format!("https://{host}/{}/did.json", path.join("/")))
    }
}

/// Resolve a `did:web` DID document over HTTPS and verify the envelope against
/// its Ed25519 verification method. Network lives here (not in tenzro-identity).
pub(crate) async fn verify_did_web_envelope(
    egress: &crate::egress_guard::EgressGuard,
    envelope: &tenzro_identity::envelope::TenzroDidEnvelope,
) -> VerificationResponse {
    fn fail(did: &str, msg: String) -> VerificationResponse {
        VerificationResponse {
            valid: false,
            details: serde_json::json!({ "error": msg, "did": did }),
            verified_at: Utc::now().to_rfc3339(),
        }
    }
    let url = match did_web_url(&envelope.did) {
        Some(u) => u,
        None => return fail(&envelope.did, "malformed did:web identifier".to_string()),
    };
    // The host comes from the DID, which the caller chose, so the fetch goes
    // through the egress guard: `did:web:169.254.169.254` must not make the
    // node read its own metadata service. Envelope verification is on the
    // request path of a caller waiting on the answer, so the fetch also gets a
    // tighter budget than the default and a small body cap; a DID document is
    // a few kilobytes.
    const DID_DOCUMENT_MAX_BYTES: usize = 64 * 1024;
    let request = match egress.get(&url, crate::egress_guard::Scheme::HttpsOnly) {
        Ok(r) => r.timeout(std::time::Duration::from_secs(5)),
        Err(e) => return fail(&envelope.did, format!("did:web fetch refused: {e}")),
    };
    let resp = match egress.send(request).await {
        Ok(r) if r.status().is_success() => r.with_limit(DID_DOCUMENT_MAX_BYTES),
        Ok(r) => {
            return fail(
                &envelope.did,
                format!("did:web fetch failed: HTTP {}", r.status()),
            );
        }
        Err(e) => return fail(&envelope.did, format!("did:web fetch failed: {e}")),
    };
    let doc: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => return fail(&envelope.did, format!("did.json parse failed: {e}")),
    };
    let key = match tenzro_identity::envelope::p256_from_did_document(&doc) {
        Some(k) => k,
        None => {
            return fail(
                &envelope.did,
                "no P-256 verification method in did.json".to_string(),
            );
        }
    };
    match tenzro_identity::envelope::verify_envelope_with_key(envelope, &key) {
        Ok(()) => VerificationResponse {
            valid: true,
            details: serde_json::json!({
                "did": envelope.did, "method": envelope.method, "resolved_via": "did:web",
            }),
            verified_at: Utc::now().to_rfc3339(),
        },
        Err(e) => fail(&envelope.did, e.to_string()),
    }
}

/// `POST /verify/did-envelope` — verify a protocol-neutral Tenzro DID envelope
/// carried in the `X-Tenzro-DID-Envelope` header (compact carriage codec)
/// against the node's identity registry. Returns `valid: true` plus the
/// resolved DID/method, or `valid: false` plus the reason. `did:key` signers
/// verify without a registry entry (key is carried in the identifier).
///
/// This is the first concrete bridge to adopt the shared
/// `tenzro_identity::envelope` core (agent-interop-protocol-bridge.md Layer 1).
pub async fn verify_did_envelope(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Json<VerificationResponse> {
    let now = || Utc::now().to_rfc3339();

    let hv = match headers
        .get("x-tenzro-did-envelope")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s,
        None => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": "missing X-Tenzro-DID-Envelope header" }),
                verified_at: now(),
            });
        }
    };

    let envelope = match tenzro_identity::envelope::TenzroDidEnvelope::from_header_value(hv) {
        Ok(e) => e,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": format!("malformed envelope: {e}") }),
                verified_at: now(),
            });
        }
    };

    let node = match &state.node {
        Some(n) => n,
        None => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": "node not available" }),
                verified_at: now(),
            });
        }
    };
    // did:web signers resolve over the network — no registry entry needed.
    if envelope.did.starts_with("did:web:") {
        return Json(verify_did_web_envelope(node.egress(), &envelope).await);
    }
    let registry = match node.identity_registry() {
        Some(r) => r,
        None => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": "identity registry not initialized" }),
                verified_at: now(),
            });
        }
    };

    match tenzro_identity::envelope::verify_envelope(&envelope, registry) {
        Ok(()) => Json(VerificationResponse {
            valid: true,
            details: serde_json::json!({ "did": envelope.did, "method": envelope.method }),
            verified_at: now(),
        }),
        Err(e) => Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({ "error": e.to_string(), "did": envelope.did }),
            verified_at: now(),
        }),
    }
}

/// `POST /verify/zk-proof` — verify one proof leg of a statement.
///
/// Runs the same verification as `tenzro_verifyZkProof`
/// ([`crate::zk_rpc::verify_statement`]). `valid: true` only on
/// cryptographic success; a single leg never reaches the attestation quorum.
pub async fn verify_zk_proof(
    State(state): State<Arc<WebState>>,
    Json(request): Json<VerifyZkProofRequest>,
) -> Json<VerificationResponse> {
    let now = || Utc::now().to_rfc3339();

    if request.circuit_id.is_empty() {
        return Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({
                "error": "circuit_id is required (\"identity\" or \"settlement\")",
            }),
            verified_at: now(),
        });
    }
    let circuit_id = request.circuit_id.clone();
    let Some(system) = tenzro_zk::ProofSystem::parse(&request.system) else {
        return Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({
                "error": format!(
                    "system must be one of {:?}",
                    tenzro_zk::ProofSystem::ALL.map(|s| s.as_str())
                ),
            }),
            verified_at: now(),
        });
    };

    // Decode proof bytes from hex
    let proof_hex = request
        .proof_bytes
        .strip_prefix("0x")
        .unwrap_or(&request.proof_bytes);
    let proof_bytes = match hex::decode(proof_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid proof_bytes hex: {}", e),
                }),
                verified_at: now(),
            });
        }
    };

    // Decode public inputs from hex
    let mut public_inputs = Vec::new();
    for (i, input_hex) in request.public_inputs.iter().enumerate() {
        let hex_str = input_hex.strip_prefix("0x").unwrap_or(input_hex);
        match hex::decode(hex_str) {
            Ok(b) => public_inputs.push(b),
            Err(e) => {
                return Json(VerificationResponse {
                    valid: false,
                    details: serde_json::json!({
                        "error": format!("Invalid public_input[{}] hex: {}", i, e),
                    }),
                    verified_at: now(),
                });
            }
        }
    }

    let details = crate::zk_rpc::verify_statement(
        state.node.as_ref(),
        circuit_id,
        public_inputs,
        vec![(system, proof_bytes)],
    )
    .await;
    Json(VerificationResponse {
        valid: details["valid"] == true,
        details,
        verified_at: now(),
    })
}

/// Verify a TEE attestation with `tenzro_tee::verify_report`.
///
/// The caller names the user data the report must carry (its challenge);
/// the report is valid only if the vendor signed exactly that.
pub async fn verify_tee_attestation(
    Json(request): Json<VerifyTeeAttestationRequest>,
) -> Json<VerificationResponse> {
    // Parse vendor
    let vendor = match request.vendor.to_lowercase().as_str() {
        "intel_tdx" | "tdx" => TeeVendor::IntelTdx,
        "amd_sev_snp" | "sev_snp" | "sev-snp" => TeeVendor::AmdSevSnp,
        "aws_nitro" | "nitro" => TeeVendor::AwsNitro,
        "nvidia_gpu" | "nvidia" => TeeVendor::NvidiaGpu,
        "intel_sgx" | "sgx" => TeeVendor::IntelSGX,
        _ => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Unknown TEE vendor: {}", request.vendor),
                    "supported": ["intel_tdx", "amd_sev_snp", "aws_nitro", "nvidia_gpu", "intel_sgx"],
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // Decode attestation report data from hex
    let report_hex = request
        .report_data
        .strip_prefix("0x")
        .unwrap_or(&request.report_data);
    let attestation_data = match hex::decode(report_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid report_data hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // Parse certificate chain if provided
    let certificates: Vec<Vec<u8>> = match request
        .certificate_chain
        .as_ref()
        .map(|certs| {
            certs
                .iter()
                .map(|pem| {
                    tenzro_tee::x509::parse_pem_chain(pem).map(|c| c.into_iter().map(|c| c.der))
                })
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()
    {
        Ok(chains) => chains.into_iter().flatten().flatten().collect(),
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": format!("Invalid certificate_chain PEM: {e}") }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // Parse expected measurement if provided
    let measurement = request
        .measurement
        .as_ref()
        .and_then(|m| {
            let hex_str = m.strip_prefix("0x").unwrap_or(m);
            hex::decode(hex_str).ok()
        })
        .unwrap_or_default();

    let expected_user_data = match hex::decode(
        request
            .expected_user_data
            .strip_prefix("0x")
            .unwrap_or(&request.expected_user_data),
    ) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": format!("Invalid expected_user_data hex: {}", e) }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    let report = AttestationReport {
        id: uuid::Uuid::new_v4(),
        vendor,
        user_data: expected_user_data.clone(),
        attestation_data,
        certificates,
        timestamp: Timestamp::now(),
        metadata: request.metadata.clone().unwrap_or_default(),
        quote: Vec::new(),
        measurement: measurement.clone(),
        signature: Vec::new(),
        vendor_data: Vec::new(),
    };

    match tenzro_tee::verify_report(&report, &tenzro_tee::VerifyPolicy::now(expected_user_data)) {
        Ok(verified) => {
            // An expected measurement, when given, must be the signed one.
            let measurement_ok = measurement.is_empty() || measurement == verified.measurement;
            let details = serde_json::json!({
                "vendor": format!("{:?}", verified.vendor),
                "tcb_status": verified.tcb_status,
                "measurement": hex::encode(&verified.measurement),
                "measurement_matches": measurement_ok,
                "status": "tee_cryptographic_verification",
            });
            Json(VerificationResponse {
                valid: measurement_ok,
                details,
                verified_at: Utc::now().to_rfc3339(),
            })
        }
        Err(e) => Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({
                "vendor": request.vendor,
                "error": format!("{}", e),
                "status": "tee_verification_failed",
            }),
            verified_at: Utc::now().to_rfc3339(),
        }),
    }
}

/// Verify a transaction signature using tenzro-crypto
pub async fn verify_transaction(
    Json(request): Json<VerifyTransactionRequest>,
) -> Json<VerificationResponse> {
    // Decode transaction hash (the message that was signed)
    let hash_hex = request
        .tx_hash
        .strip_prefix("0x")
        .unwrap_or(&request.tx_hash);
    let tx_hash_bytes = match hex::decode(hash_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid tx_hash hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    let decode = |field: &str, value: &str| -> Result<Vec<u8>, Json<VerificationResponse>> {
        hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|e| {
            Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({ "error": format!("Invalid {field} hex: {e}") }),
                verified_at: Utc::now().to_rfc3339(),
            })
        })
    };
    let sender_bytes = match decode("sender", &request.sender) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let enrolled = match request
        .ml_dsa_public_key
        .as_deref()
        .map(|k| decode("ml_dsa_public_key", k))
    {
        Some(Ok(b)) => Some(b),
        Some(Err(resp)) => return resp,
        None => None,
    };

    // Each leg is checked on its own so the response can say which one
    // failed. The ML-DSA-65 leg is required when the account enrolled a key.
    use tenzro_crypto::composite::{
        PqPolicy, SignatureContext, verify_classical_component, verify_pq_component,
    };
    let (classical_valid, classical_status) = match verify_classical_component(
        &sender_bytes,
        SignatureContext::Transaction,
        &tx_hash_bytes,
        &request.signature.classical,
    ) {
        Ok(()) => (true, "p256_signature_valid"),
        Err(_) => (false, "p256_signature_invalid"),
    };
    let policy = if enrolled.is_some() {
        PqPolicy::Required
    } else {
        PqPolicy::WhenPresent
    };
    let (pq_valid, pq_status) = match verify_pq_component(
        enrolled.as_deref(),
        SignatureContext::Transaction,
        &tx_hash_bytes,
        request.signature.pq.as_deref(),
        policy,
    ) {
        Ok(legs) if legs.pq => (true, "ml_dsa_65_signature_valid"),
        Ok(_) => (true, "ml_dsa_65_not_enrolled"),
        Err(_) => (false, "ml_dsa_65_signature_invalid"),
    };
    let valid = classical_valid && pq_valid;

    let details = serde_json::json!({
        "tx_hash": request.tx_hash,
        "sender": request.sender,
        "sender_key_size": sender_bytes.len(),
        "has_pq_leg": request.signature.pq.is_some(),
        "has_data": request.data.is_some(),
        "classical_status": classical_status,
        "pq_status": pq_status,
        "status": if valid { "signature_valid" } else { "signature_invalid" },
    });

    Json(VerificationResponse {
        valid,
        details,
        verified_at: Utc::now().to_rfc3339(),
    })
}

/// Verify a settlement proof using tenzro-settlement verifiers
pub async fn verify_settlement(
    Json(request): Json<VerifySettlementRequest>,
) -> Json<VerificationResponse> {
    // If no proof provided, we can only validate the receipt metadata
    let proof_data = match &request.proof_of_service {
        Some(hex_str) => {
            let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
            match hex::decode(stripped) {
                Ok(b) => Some(b),
                Err(e) => {
                    return Json(VerificationResponse {
                        valid: false,
                        details: serde_json::json!({
                            "error": format!("Invalid proof_of_service hex: {}", e),
                        }),
                        verified_at: Utc::now().to_rfc3339(),
                    });
                }
            }
        }
        None => None,
    };

    // Validate settlement metadata
    let amount_valid = request
        .amount
        .parse::<f64>()
        .map(|a| a > 0.0)
        .unwrap_or(false);
    let payer_valid = !request.payer.is_empty();
    let payee_valid = !request.payee.is_empty();
    let receipt_valid = !request.receipt_id.is_empty();

    let (valid, status) = if let Some(ref proof_bytes) = proof_data {
        // Attempt to deserialize as a ServiceProof and verify
        // Try JSON deserialization first (ServiceProof is serde-compatible)
        match serde_json::from_slice::<tenzro_types::settlement::ServiceProof>(proof_bytes) {
            Ok(proof) => {
                use tenzro_types::settlement::ProofType as SettlementProofType;
                // Verify based on proof type
                match proof.proof_type {
                    SettlementProofType::ZeroKnowledge => {
                        // The proof data is a JSON proof envelope; it counts
                        // only if the STARK verifier accepts it.
                        let zk_valid = verify_zk_envelope_bytes(proof.proof_data.clone()).await;
                        (
                            zk_valid && amount_valid,
                            if zk_valid {
                                "settlement_zk_proof_verified"
                            } else {
                                "settlement_zk_proof_rejected"
                            },
                        )
                    }
                    SettlementProofType::TeeAttestation => {
                        // Only a vendor-signed report counts; there is no
                        // structural fallback.
                        match serde_json::from_slice::<AttestationReport>(&proof.proof_data) {
                            Ok(report) => {
                                // The report must commit to this settlement,
                                // not to whatever data it happens to carry.
                                let binding = claim_binding(
                                    b"tenzro/verify/settlement",
                                    &[
                                        &request.receipt_id,
                                        &request.payer,
                                        &request.payee,
                                        &request.amount,
                                        &request.asset,
                                    ],
                                );
                                let expected = tenzro_types::tee::pack_user_data_for_vendor(
                                    report.vendor,
                                    &binding,
                                );
                                let policy = tenzro_tee::VerifyPolicy::now(expected);
                                let tee_valid = tenzro_tee::verify_report(&report, &policy).is_ok();
                                (
                                    tee_valid && amount_valid,
                                    "settlement_tee_attestation_verified",
                                )
                            }
                            Err(_) => (false, "settlement_tee_attestation_unparseable"),
                        }
                    }
                    SettlementProofType::Cryptographic => {
                        // Verify Ed25519 signature presence in proof
                        let has_signature = proof.proof_data.len() >= 64;
                        let has_signatures = !proof.signatures.is_empty();
                        (
                            has_signature && has_signatures && amount_valid,
                            "settlement_cryptographic_verified",
                        )
                    }
                    SettlementProofType::MultiParty => {
                        // Multi-party proof — verify sufficient signatures
                        let has_signatures = proof.signatures.len() >= 2;
                        (
                            has_signatures && amount_valid,
                            "settlement_multiparty_verified",
                        )
                    }
                    SettlementProofType::Merkle => {
                        // Merkle proof — validate minimum size
                        let merkle_valid = proof.proof_data.len() >= 32;
                        (merkle_valid && amount_valid, "settlement_merkle_verified")
                    }
                    SettlementProofType::Oracle => {
                        // Oracle proof — verify oracle signature present
                        let has_signature = !proof.signatures.is_empty();
                        (has_signature && amount_valid, "settlement_oracle_verified")
                    }
                }
            }
            Err(_) => {
                // Raw proof bytes — structural validation
                let structural_valid = proof_bytes.len() >= 32 && amount_valid;
                (structural_valid, "settlement_raw_structural_validation")
            }
        }
    } else {
        // No proof — validate metadata only
        let metadata_valid = amount_valid && payer_valid && payee_valid && receipt_valid;
        (metadata_valid, "metadata_validation_only")
    };

    let details = serde_json::json!({
        "receipt_id": request.receipt_id,
        "payer": request.payer,
        "payee": request.payee,
        "amount": request.amount,
        "asset": request.asset,
        "has_proof": proof_data.is_some(),
        "proof_size_bytes": proof_data.as_ref().map(|p| p.len()).unwrap_or(0),
        "amount_valid": amount_valid,
        "status": status,
    });

    Json(VerificationResponse {
        valid,
        details,
        verified_at: Utc::now().to_rfc3339(),
    })
}

/// Verify an inference result using ZK proof and/or TEE attestation
pub async fn verify_inference(
    Json(request): Json<VerifyInferenceRequest>,
) -> Json<VerificationResponse> {
    let has_tee = request.tee_attestation.is_some();
    let has_zk = request.zk_proof.is_some();

    // At least one verification method must be provided
    if !has_tee && !has_zk {
        return Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({
                "error": "At least one of tee_attestation or zk_proof must be provided",
                "model_id": request.model_id,
                "provider": request.provider,
            }),
            verified_at: Utc::now().to_rfc3339(),
        });
    }

    let mut tee_valid = None;
    let mut tee_status = "not_provided";
    let mut zk_valid = None;
    let mut zk_status = "not_provided";

    // Verify TEE attestation if provided
    if let Some(ref att_hex) = request.tee_attestation {
        let stripped = att_hex.strip_prefix("0x").unwrap_or(att_hex);
        match hex::decode(stripped) {
            Ok(att_bytes) => {
                // Try to deserialize as AttestationReport
                match serde_json::from_slice::<AttestationReport>(&att_bytes) {
                    Ok(report) => {
                        // The report must commit to this inference: the
                        // model, the provider, and the input and output.
                        let binding = claim_binding(
                            b"tenzro/verify/inference",
                            &[
                                &request.model_id,
                                &request.provider,
                                &request.input_hash,
                                &request.output_hash,
                            ],
                        );
                        let expected =
                            tenzro_types::tee::pack_user_data_for_vendor(report.vendor, &binding);
                        let policy = tenzro_tee::VerifyPolicy::now(expected);
                        let ok = tenzro_tee::verify_report(&report, &policy).is_ok();
                        tee_valid = Some(ok);
                        tee_status = if ok {
                            "tee_attestation_valid"
                        } else {
                            "tee_attestation_invalid"
                        };
                    }
                    Err(_) => {
                        // Only a vendor-signed report counts.
                        tee_valid = Some(false);
                        tee_status = "tee_attestation_unparseable";
                    }
                }
            }
            Err(_) => {
                tee_valid = Some(false);
                tee_status = "invalid_tee_hex";
            }
        }
    }

    // Verify ZK proof if provided
    if let Some(ref proof_hex) = request.zk_proof {
        let stripped = proof_hex.strip_prefix("0x").unwrap_or(proof_hex);
        match hex::decode(stripped) {
            Ok(proof_bytes) => {
                // A JSON proof envelope, accepted only if the STARK verifier
                // accepts it. No circuit proves model inference, so this
                // attests to the proven statement, not to the model output.
                let proof_valid = verify_zk_envelope_bytes(proof_bytes).await;
                zk_valid = Some(proof_valid);
                zk_status = if proof_valid {
                    "zk_proof_verified"
                } else {
                    "zk_proof_rejected"
                };
            }
            Err(_) => {
                zk_valid = Some(false);
                zk_status = "invalid_zk_hex";
            }
        }
    }

    // Overall validity: all provided proofs must be valid
    let valid = tee_valid.unwrap_or(true) && zk_valid.unwrap_or(true);

    let details = serde_json::json!({
        "model_id": request.model_id,
        "provider": request.provider,
        "input_hash": request.input_hash,
        "output_hash": request.output_hash,
        "tee_attestation_provided": has_tee,
        "tee_verification_status": tee_status,
        "zk_proof_provided": has_zk,
        "zk_verification_status": zk_status,
        "status": if valid { "inference_verified" } else { "inference_verification_failed" },
    });

    Json(VerificationResponse {
        valid,
        details,
        verified_at: Utc::now().to_rfc3339(),
    })
}

/// Health check endpoint
///
/// `status` reflects overall node health (any subsystem degraded → "degraded").
/// `verification_service` reflects whether the verification API stack is functional
/// — true unless a verification-critical subsystem (auth, identity, vm) is
/// `Unhealthy`. TEE/network/etc being merely `Degraded` does not break verification:
/// the API can still serve ZK proof, transaction signature, settlement, and remote
/// attestation verification (all crypto-only paths that don't require local TEE).
/// `GET /.well-known/did.json` — this node's self-published DID Document.
///
/// The W3C well-known path, so a generic DID resolver reaches it without
/// knowing anything Tenzro-specific. Returns 404 when the node has no
/// provisioned identity: a document for a DID that does not exist would
/// resolve to nothing anywhere else, and inventing one is worse than saying
/// there is none.
pub async fn node_did_document(State(state): State<Arc<WebState>>) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(node) = state.node.as_ref() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no node attached to this web server" })),
        )
            .into_response();
    };

    let addressing = node.self_addressing().await;
    match crate::node_did_document::publish(&addressing) {
        Some(doc) => (
            axum::http::StatusCode::OK,
            // The registered media type for a DID Document, so a generic
            // resolver content-negotiates correctly rather than guessing.
            [(axum::http::header::CONTENT_TYPE, "application/did+json")],
            Json(doc),
        )
            .into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "this node has no provisioned identity, so it has no DID Document"
            })),
        )
            .into_response(),
    }
}

pub async fn health(State(state): State<Arc<WebState>>) -> Json<HealthResponse> {
    let (status, verification_service) = if let Some(ref node) = state.node {
        let monitor = node.health_monitor();
        let overall = monitor.check_health();
        let status_str = match overall {
            crate::health::OverallHealth::Healthy => "healthy",
            crate::health::OverallHealth::Degraded => "degraded",
            crate::health::OverallHealth::Unhealthy => "unhealthy",
            crate::health::OverallHealth::Unknown => "unknown",
        }
        .to_string();

        // Verification API works as long as no verification-critical subsystem is Unhealthy.
        // Critical subsystems for the verify endpoints: auth, identity, vm.
        // TEE being absent is fine — remote attestation verification is crypto-only.
        let verify_ok = monitor.subsystem_is_ok("auth")
            && monitor.subsystem_is_ok("identity")
            && monitor.subsystem_is_ok("vm");

        (status_str, verify_ok)
    } else {
        ("healthy".to_string(), true)
    };

    Json(HealthResponse {
        status,
        version: state.node_version.clone(),
        verification_service,
    })
}

/// Readiness endpoint for K8s readinessProbe / load-balancer gating.
///
/// Returns HTTP 200 with `ready: true` only when this node has caught up
/// to the network on block height and, on a validator, its certificates
/// keep up with its ordering. Returns HTTP 503 with `ready: false` and a
/// `reason` string otherwise — matches the standard pattern of separating
/// liveness (`/health`) from production-traffic readiness (`/ready`).
///
/// Tolerances:
///   * `block_lag_tolerance = 5`  — typical mempool churn
///   * `certification_lag_tolerance = 100` heights — several checkpoints
///
/// When network tip is unknown (no fresh peer status), readiness gates
/// purely on `peer_count >= 1`, so a fresh testnet bootstrap can come up.
pub async fn ready(State(state): State<Arc<WebState>>) -> (StatusCode, Json<ReadyResponse>) {
    const BLOCK_LAG_TOLERANCE: u64 = 5;
    const CERTIFICATION_LAG_TOLERANCE: u64 = 100;

    let Some(ref node) = state.node else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                block_height: 0,
                network_tip: None,
                block_lag: None,
                certified_height: 0,
                peer_count: 0,
                reason: "node not initialized".to_string(),
            }),
        );
    };

    let node_status = node.status().await;
    let block_height = node_status.block_height;
    let peer_count = node_status.peer_count;
    let network_tip = node.network_tip();
    let certified_height = node.consensus().map(|c| c.certified_height()).unwrap_or(0);
    // A follower imports only certified blocks, so its certificates cannot
    // lag its tip. Block lag is the whole readiness signal there.
    let votes = node.consensus().is_some_and(|c| c.is_validator());

    // Compute block lag against network tip if available.
    let block_lag = network_tip.map(|tip| tip.saturating_sub(block_height));

    // Gating logic.
    //
    // Peers are a readiness requirement only for a node that needs the
    // network to do its job. A validator with no peers cannot participate in
    // consensus and is genuinely not ready. A model-serving node running
    // isolated has nothing to sync and serves inference perfectly well with
    // zero peers — failing its readiness probe would have a load balancer
    // pull a healthy node out of rotation, and made `/ready` disagree with
    // `/status`, which reported the same node as "All systems operational".
    //
    // "Isolated" is the operator's explicit choice (`--boot-nodes ""`), not
    // an inference from an empty peer list: a node that WAS given bootstrap
    // peers and has none connected has failed to join, and that is a real
    // readiness failure worth reporting.
    let isolated = node.config().iroh.boot.is_empty();
    let (ready, reason) = if peer_count == 0 && !isolated {
        (false, "no peers".to_string())
    } else if let Some(tip) = network_tip {
        let lag = tip.saturating_sub(block_height);
        if lag > BLOCK_LAG_TOLERANCE {
            (
                false,
                format!(
                    "block lag {} > tolerance {} (local {} vs network {})",
                    lag, BLOCK_LAG_TOLERANCE, block_height, tip
                ),
            )
        } else {
            // Block height caught up; on a validator, check that its
            // checkpoints are being certified.
            if votes && certified_height + CERTIFICATION_LAG_TOLERANCE < block_height {
                (
                    false,
                    format!(
                        "certified height {} lags block height {} by > {}",
                        certified_height, block_height, CERTIFICATION_LAG_TOLERANCE
                    ),
                )
            } else {
                (true, "caught up".to_string())
            }
        }
    } else if isolated {
        // Deliberately isolated: there is no network to be behind, so there is
        // nothing to be ready *for* beyond the services being up.
        (true, "isolated node; services up".to_string())
    } else {
        // Bootstrapping: peers exist (the check above would have caught zero)
        // but none has reported a tip yet, so there is nothing to measure lag
        // against. Ready rather than blocked, or a fresh network could never
        // come up — every node would wait for a tip nobody can publish.
        (
            true,
            format!("no network tip yet; {peer_count} peer(s) connected"),
        )
    };

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(ReadyResponse {
            ready,
            block_height,
            network_tip,
            block_lag,
            certified_height,
            peer_count,
            reason,
        }),
    )
}

/// Node status endpoint
pub async fn status(State(state): State<Arc<WebState>>) -> Json<NodeStatusResponse> {
    if let Some(ref node) = state.node {
        let node_status = node.status().await;
        let health_status = node.health_monitor().get_status(
            BlockHeight::from(node_status.block_height),
            node_status.peer_count as usize,
        );
        Json(NodeStatusResponse {
            node_state: node_status.state,
            roles: node_status
                .roles
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            health: format!("{:?}", node_status.health_status),
            block_height: node_status.block_height,
            peer_count: node_status.peer_count,
            uptime_secs: node_status.uptime_secs,
            ready: health_status.is_ready(),
            status_message: health_status.status_message(),
        })
    } else {
        Json(NodeStatusResponse {
            node_state: "running".to_string(),
            roles: Vec::new(),
            health: "healthy".to_string(),
            block_height: 0,
            peer_count: 0,
            uptime_secs: 0,
            ready: false,
            status_message: "Node not initialized".to_string(),
        })
    }
}

/// Prometheus metrics endpoint — exports metrics in Prometheus text exposition format
pub async fn prometheus_metrics(State(state): State<Arc<WebState>>) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let metrics = match &state.metrics {
        Some(m) => m.get_metrics(),
        None => crate::metrics::NodeMetrics {
            blocks_processed: 0,
            transactions_processed: 0,
            inference_requests: 0,
            settlements: 0,
            settled_value: 0,
            peer_count: 0,
            uptime_secs: 0,
        },
    };

    // Build Prometheus text exposition format (OpenMetrics compatible)
    let mut body = String::with_capacity(2048);

    // Node info
    body.push_str("# HELP tenzro_node_info Node version and role information\n");
    body.push_str("# TYPE tenzro_node_info gauge\n");
    body.push_str(&format!(
        "tenzro_node_info{{version=\"{}\"}} 1\n\n",
        state.node_version
    ));

    // Uptime
    body.push_str("# HELP tenzro_node_uptime_seconds Node uptime in seconds\n");
    body.push_str("# TYPE tenzro_node_uptime_seconds counter\n");
    body.push_str(&format!(
        "tenzro_node_uptime_seconds {}\n\n",
        metrics.uptime_secs
    ));

    // Blocks
    body.push_str("# HELP tenzro_blocks_processed_total Total blocks processed\n");
    body.push_str("# TYPE tenzro_blocks_processed_total counter\n");
    body.push_str(&format!(
        "tenzro_blocks_processed_total {}\n\n",
        metrics.blocks_processed
    ));

    // Transactions
    body.push_str("# HELP tenzro_transactions_processed_total Total transactions processed\n");
    body.push_str("# TYPE tenzro_transactions_processed_total counter\n");
    body.push_str(&format!(
        "tenzro_transactions_processed_total {}\n\n",
        metrics.transactions_processed
    ));

    // Inference
    body.push_str("# HELP tenzro_inference_requests_total Total AI inference requests handled\n");
    body.push_str("# TYPE tenzro_inference_requests_total counter\n");
    body.push_str(&format!(
        "tenzro_inference_requests_total {}\n\n",
        metrics.inference_requests
    ));

    // Settlements
    body.push_str("# HELP tenzro_settlements_total Total settlements processed\n");
    body.push_str("# TYPE tenzro_settlements_total counter\n");
    body.push_str(&format!(
        "tenzro_settlements_total {}\n\n",
        metrics.settlements
    ));

    // Peers
    body.push_str("# HELP tenzro_peer_count Current number of connected peers\n");
    body.push_str("# TYPE tenzro_peer_count gauge\n");
    body.push_str(&format!("tenzro_peer_count {}\n\n", metrics.peer_count));

    // Derived rate gauges (computed from cumulative counters + uptime)
    body.push_str(
        "# HELP tenzro_blocks_per_second Average blocks processed per second since node start\n",
    );
    body.push_str("# TYPE tenzro_blocks_per_second gauge\n");
    body.push_str(&format!(
        "tenzro_blocks_per_second {:.4}\n\n",
        metrics.blocks_per_second()
    ));

    body.push_str("# HELP tenzro_transactions_per_second Average transactions processed per second since node start\n");
    body.push_str("# TYPE tenzro_transactions_per_second gauge\n");
    body.push_str(&format!(
        "tenzro_transactions_per_second {:.4}\n\n",
        metrics.transactions_per_second()
    ));

    // Uptime info metric — value is always 1; human-readable form lives in the label
    body.push_str("# HELP tenzro_node_uptime_info Node uptime in human-readable form\n");
    body.push_str("# TYPE tenzro_node_uptime_info gauge\n");
    body.push_str(&format!(
        "tenzro_node_uptime_info{{uptime=\"{}\"}} 1\n\n",
        metrics.uptime_human()
    ));

    // Node health
    if let Some(ref node) = state.node {
        let status = node.status().await;
        let health_val = match status.health_status {
            crate::health::OverallHealth::Healthy => 1,
            crate::health::OverallHealth::Degraded => 0,
            crate::health::OverallHealth::Unhealthy => -1,
            crate::health::OverallHealth::Unknown => -2,
        };
        body.push_str(
            "# HELP tenzro_node_health Node health status (1=healthy, 0=degraded, -1=unhealthy)\n",
        );
        body.push_str("# TYPE tenzro_node_health gauge\n");
        body.push_str(&format!("tenzro_node_health {}\n\n", health_val));

        body.push_str("# HELP tenzro_block_height Current block height\n");
        body.push_str("# TYPE tenzro_block_height gauge\n");
        body.push_str(&format!("tenzro_block_height {}\n\n", status.block_height));

        // Model services count
        let model_count = node.list_model_services().len();
        body.push_str(
            "# HELP tenzro_model_services_count Number of active model service instances\n",
        );
        body.push_str("# TYPE tenzro_model_services_count gauge\n");
        body.push_str(&format!("tenzro_model_services_count {}\n\n", model_count));
    }

    // Append network-layer metrics (gossip, dial rate limits, peer counts, etc.)
    // These are registered into the shared Prometheus `Registry` at service
    // startup (see `tenzro_network::NetworkMetrics::register`). We serialize
    // them here using the `prometheus_client` text encoder.
    if let Some(registry) = &state.network_metrics_registry {
        let registry_guard = registry.lock();
        if let Err(e) = prometheus_client::encoding::text::encode(&mut body, &registry_guard) {
            // A failure here is non-fatal — emit a comment so operators
            // can diagnose, but still return the partial response.
            tracing::warn!("Failed to encode network metrics registry: {}", e);
            body.push_str(&format!("# ERROR encoding network metrics: {}\n", e));
        }
    }

    // Append stream-level SLO metrics (P1.3): tenzro_inference_ttft_seconds,
    // tenzro_inference_intertoken_seconds (histograms), and the
    // started/completed/failed counters. Labels: (provider, model).
    // Observations are made inline by the SSE handlers in `rpc.rs` —
    // here we just serialize the current state.
    if let Some(ref node) = state.node {
        node.stream_slo_metrics.encode_prometheus(&mut body);
        // Administrative calls by method and outcome.
        node.admin_audit().encode_prometheus(&mut body);
    }

    // Append per-DID admission lane metrics. The
    // AdmissionController keeps cumulative LaneStats counters; the
    // mempool exposes per-lane queue depth via `lane_depths()` which
    // walks `transactions` and re-resolves each lane (O(n), only run
    // on scrape — typically 10–60s).
    //
    // Emitted series:
    //   - tenzro_mempool_admitted_total{lane}             (counter)
    //   - tenzro_mempool_rejected_total{lane,reason}      (counter; reason ∈ rate_limited|fee_floor|mempool_full)
    //   - tenzro_mempool_queue_depth{lane}                (gauge)
    //   - tenzro_mempool_bucket_count                     (gauge)
    if let Some(ref node) = state.node
        && let Some(admission) = node.admission()
    {
        use tenzro_consensus::admission::Lane;

        let stats = admission.stats();

        // admitted_total{lane}
        body.push_str("# HELP tenzro_mempool_admitted_total Transactions admitted to the mempool, broken down by admission lane\n");
        body.push_str("# TYPE tenzro_mempool_admitted_total counter\n");
        for lane in Lane::all() {
            body.push_str(&format!(
                "tenzro_mempool_admitted_total{{lane=\"{}\"}} {}\n",
                lane.as_str(),
                stats.admitted(lane),
            ));
        }
        body.push('\n');

        // rejected_total{lane,reason}
        body.push_str("# HELP tenzro_mempool_rejected_total Transactions rejected at admission, broken down by lane and reason\n");
        body.push_str("# TYPE tenzro_mempool_rejected_total counter\n");
        for lane in Lane::all() {
            body.push_str(&format!(
                "tenzro_mempool_rejected_total{{lane=\"{}\",reason=\"rate_limited\"}} {}\n",
                lane.as_str(),
                stats.rejected_rate_limited(lane),
            ));
            body.push_str(&format!(
                "tenzro_mempool_rejected_total{{lane=\"{}\",reason=\"fee_floor\"}} {}\n",
                lane.as_str(),
                stats.rejected_fee_floor(lane),
            ));
            body.push_str(&format!(
                "tenzro_mempool_rejected_total{{lane=\"{}\",reason=\"mempool_full\"}} {}\n",
                lane.as_str(),
                stats.rejected_mempool_full(lane),
            ));
        }
        body.push('\n');

        // bucket_count (gauge — the number of distinct controllers
        // with a live token bucket on this validator)
        body.push_str("# HELP tenzro_mempool_bucket_count Number of distinct controllers with an active per-DID admission bucket on this validator\n");
        body.push_str("# TYPE tenzro_mempool_bucket_count gauge\n");
        body.push_str(&format!(
            "tenzro_mempool_bucket_count {}\n\n",
            stats.bucket_count
        ));

        // queue_depth{lane} — only emitted when consensus is wired
        // (the mempool lives on the consensus engine).
        if let Some(consensus) = node.consensus() {
            let depths = consensus.mempool().lane_depths();
            body.push_str("# HELP tenzro_mempool_queue_depth Current number of pending transactions in the mempool, broken down by lane\n");
            body.push_str("# TYPE tenzro_mempool_queue_depth gauge\n");
            for lane in Lane::all() {
                body.push_str(&format!(
                    "tenzro_mempool_queue_depth{{lane=\"{}\"}} {}\n",
                    lane.as_str(),
                    depths[lane as usize],
                ));
            }
            body.push('\n');
        }
    }

    // Consensus liveness + safety metrics for on-call alerting.
    // Emitted whenever the consensus engine is wired, independent of
    // the admission controller. The two page-worthy signals:
    //   - tenzro_consensus_last_certified_age_seconds growing without
    //     bound → a certification stall
    //   - tenzro_consensus_equivocation_evidence > 0 → a validator signed
    //     two checkpoints with one index (slashable)
    if let Some(ref node) = state.node
        && let Some(consensus) = node.consensus()
    {
        let finality = consensus.finality();
        body.push_str("# HELP tenzro_consensus_round Round this validator last proposed in\n");
        body.push_str("# TYPE tenzro_consensus_round gauge\n");
        body.push_str(&format!("tenzro_consensus_round {}\n\n", consensus.round()));

        body.push_str("# HELP tenzro_consensus_ordered_height Highest height ordered: final for every honest validator\n");
        body.push_str("# TYPE tenzro_consensus_ordered_height gauge\n");
        body.push_str(&format!(
            "tenzro_consensus_ordered_height {}\n\n",
            finality.ordered
        ));

        body.push_str("# HELP tenzro_consensus_certified_height Highest height covered by a checkpoint certificate\n");
        body.push_str("# TYPE tenzro_consensus_certified_height gauge\n");
        body.push_str(&format!(
            "tenzro_consensus_certified_height {}\n\n",
            finality.certified
        ));

        // Absent until the first certificate after boot — a scrape-side
        // `absent()` guard covers the startup window.
        if let Some(age) = consensus.seconds_since_last_certificate() {
            body.push_str("# HELP tenzro_consensus_last_certified_age_seconds Seconds since this node last recorded a checkpoint certificate\n");
            body.push_str("# TYPE tenzro_consensus_last_certified_age_seconds gauge\n");
            body.push_str(&format!(
                "tenzro_consensus_last_certified_age_seconds {}\n\n",
                age
            ));
        }

        body.push_str("# HELP tenzro_consensus_equivocation_evidence Checkpoint equivocations this validator has proof of\n");
        body.push_str("# TYPE tenzro_consensus_equivocation_evidence counter\n");
        body.push_str(&format!(
            "tenzro_consensus_equivocation_evidence {}\n\n",
            consensus.equivocations_seen()
        ));
        body.push_str("# HELP tenzro_consensus_dropped_frames Consensus frames dropped because the queue to their peer was full\n");
        body.push_str("# TYPE tenzro_consensus_dropped_frames counter\n");
        body.push_str(&format!(
            "tenzro_consensus_dropped_frames {}\n\n",
            consensus.dropped_frames()
        ));

        if let Some(m) = consensus.metrics() {
            let gauges: [(&str, &str, u64); 12] = [
                (
                    "tenzro_consensus_round_p50_ms",
                    "Median recent round duration, ms",
                    m.round_p50_ms,
                ),
                (
                    "tenzro_consensus_round_p99_ms",
                    "99th percentile recent round duration, ms",
                    m.round_p99_ms,
                ),
                (
                    "tenzro_consensus_ordered_p50_ms",
                    "Median time from first seeing a batched transaction to ordering it, ms",
                    m.ordered_p50_ms,
                ),
                (
                    "tenzro_consensus_ordered_p99_ms",
                    "99th percentile time from first seeing a batched transaction to ordering it, ms",
                    m.ordered_p99_ms,
                ),
                (
                    "tenzro_consensus_rbc_fast_total",
                    "Reliable-broadcast deliveries on the two-step path",
                    m.rbc_fast,
                ),
                (
                    "tenzro_consensus_rbc_slow_total",
                    "Reliable-broadcast deliveries on the slower path",
                    m.rbc_slow,
                ),
                (
                    "tenzro_consensus_leaders_committed_total",
                    "Leader slots committed since the core started",
                    m.leaders_committed,
                ),
                (
                    "tenzro_consensus_leaders_skipped_total",
                    "Leader slots skipped since the core started",
                    m.leaders_skipped,
                ),
                (
                    "tenzro_consensus_batches_pending",
                    "Batches introduced and not yet available",
                    m.batches_pending,
                ),
                (
                    "tenzro_consensus_certificate_bytes",
                    "Encoded size of the last certificate formed",
                    m.certificate_bytes,
                ),
                (
                    "tenzro_consensus_egress_bytes_total",
                    "Consensus bytes sent since the core started",
                    m.egress_bytes,
                ),
                (
                    "tenzro_consensus_egress_bytes_per_round",
                    "Consensus bytes sent per round over the last interval",
                    m.egress_bytes_per_round,
                ),
            ];
            for (name, help, value) in gauges {
                let kind = if name.ends_with("_total") {
                    "counter"
                } else {
                    "gauge"
                };
                body.push_str(&format!(
                    "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n\n"
                ));
            }
        }

        body.push_str("# HELP tenzro_mempool_size Total pending transactions in the mempool across all lanes\n");
        body.push_str("# TYPE tenzro_mempool_size gauge\n");
        body.push_str(&format!(
            "tenzro_mempool_size {}\n\n",
            consensus.mempool().len()
        ));
    }

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// ===== Adaptive execution: HTTP handlers =====

/// Rank a provider's announced reachability tier for routing preference:
/// higher is more reachable. `direct` outranks `relay_only`, which outranks
/// `unreachable` or an unreported tier. Mirrors `ReachabilityTier`'s
/// worst-to-best ordering so the request router can pick with `max_by_key`.
fn reachability_rank(tier: &str) -> u8 {
    match tier {
        "direct" => 2,
        "relay_only" => 1,
        _ => 0,
    }
}

/// POST /execution/resolve
/// Resolves the best execution plan for a model given client requirements.
pub async fn resolve_execution(
    State(state): State<Arc<WebState>>,
    Json(request): Json<ResolveExecutionRequest>,
) -> Json<ResolveExecutionResponse> {
    use tenzro_types::runtime::{CapabilityResolution, ExecutionPlan};

    let resolved_at = Utc::now().to_rfc3339();

    let routing = request.routing_policy.as_ref();

    let resolution = if let Some(ref node) = state.node {
        let providers = node.network_providers_snapshot();
        let maybe_provider = providers
            .iter()
            .filter(|p| p.announcement.served_models.contains(&request.model_id))
            .filter(|p| {
                // Apply routing_policy: require_attestation filters to attested providers
                if routing.is_some_and(|r| r.require_attestation) {
                    p.announcement
                        .capabilities
                        .iter()
                        .any(|c| c.contains("tee"))
                } else {
                    true
                }
            })
            // Prefer the most reachable provider (direct over relay-only over
            // an unreported tier).
            .max_by_key(|p| reachability_rank(&p.announcement.network_profile.reachability));

        if let Some(entry) = maybe_provider {
            let ann = &entry.announcement;
            let mode = request
                .required_execution
                .as_ref()
                .map(|r| r.preferred_mode)
                .unwrap_or_default();

            CapabilityResolution {
                model_id: request.model_id.clone(),
                resolved_provider: ann.iroh_endpoint_id.clone(),
                execution_plan: ExecutionPlan {
                    plan_id: format!("plan-{}", Utc::now().timestamp_millis()),
                    model_id: request.model_id.clone(),
                    provider_id: ann.iroh_endpoint_id.clone(),
                    execution_mode: mode,
                    constraints: request.placement_constraints.clone().unwrap_or_default(),
                    trust_profile: ann.trust_profile.clone(),
                    ..Default::default()
                },
                alternatives: vec![],
            }
        } else {
            CapabilityResolution {
                model_id: request.model_id.clone(),
                ..Default::default()
            }
        }
    } else {
        CapabilityResolution {
            model_id: request.model_id.clone(),
            ..Default::default()
        }
    };

    Json(ResolveExecutionResponse {
        resolution,
        resolved_at,
    })
}

/// GET /models/:model_id/artifacts
/// Returns artifact descriptors for a model discovered via gossip.
pub async fn list_model_artifacts(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(model_id): axum::extract::Path<String>,
) -> Json<ModelArtifactsResponse> {
    if let Some(ref node) = state.node {
        let models = node.network_models_snapshot();
        if let Some(entry) = models.iter().find(|m| m.registration.model_id == model_id) {
            return Json(ModelArtifactsResponse {
                model_id: entry.registration.model_id.clone(),
                artifacts: entry.registration.artifacts.clone(),
                artifact_completeness: entry.registration.artifact_completeness,
            });
        }
    }
    Json(ModelArtifactsResponse {
        model_id,
        artifacts: vec![],
        artifact_completeness: Default::default(),
    })
}

/// GET /providers
/// Lists all network providers discovered via gossip, with their runtime metadata.
pub async fn list_providers_rfc(
    State(state): State<Arc<WebState>>,
) -> Json<Vec<ProviderRuntimeInfo>> {
    if let Some(ref node) = state.node {
        let providers = node.network_providers_snapshot();
        let result: Vec<ProviderRuntimeInfo> = providers
            .into_iter()
            .map(|entry| {
                let ann = entry.announcement;
                ProviderRuntimeInfo {
                    iroh_endpoint_id: ann.iroh_endpoint_id,
                    provider_address: ann.provider_address,
                    provider_type: ann.provider_type,
                    served_models: ann.served_models,
                    capabilities: ann.capabilities,
                    status: ann.status,
                    runtime_support: ann.runtime_support,
                    network_profile: ann.network_profile,
                    trust_profile: ann.trust_profile,
                    worker_roles: ann.worker_roles,
                    is_local: false,
                }
            })
            .collect();
        return Json(result);
    }
    Json(vec![])
}

/// The report data a verification request's claim must be committed to:
/// SHA-256 of a domain tag and the length-prefixed claim fields.
fn claim_binding(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    for f in fields {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f.as_bytes());
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webstate_builder() {
        let state = WebState::new();
        assert!(state.inference_router.is_none());
    }
}
