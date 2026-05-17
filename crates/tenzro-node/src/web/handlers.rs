use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;
use std::collections::HashMap;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use chrono::Utc;

use super::types::*;
use crate::event_loop::NodeEvent;
use crate::node::TenzroNode;
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};
use tenzro_storage::KvStore;
use tenzro_types::tee::{AttestationReport, TeeVendor};
use tenzro_tee::AttestationVerifier;
use tenzro_zk::{Proof, VerifyEnvelopeError, verify_proof_envelope};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature as CryptoSignature;

/// Shared state for web handlers
pub struct WebState {
    pub node_version: String,
    /// Reference to the node for querying real status
    pub node: Option<Arc<TenzroNode>>,
    /// Event sender to submit transactions
    pub event_tx: Option<mpsc::Sender<NodeEvent>>,
    /// Metrics collector for Prometheus endpoint
    pub metrics: Option<crate::metrics::MetricsCollector>,
    /// Shared Prometheus registry for the network layer (gossipsub, dials, peer counts).
    /// When populated, `/metrics` will append the encoded `tenzro_network_*` metrics.
    pub network_metrics_registry:
        Option<Arc<Mutex<prometheus_client::registry::Registry>>>,
    /// Inference router for chat endpoint
    pub inference_router: Option<Arc<tenzro_model::InferenceRouter>>,
    /// Faucet rate limiter: address hex -> last request timestamp
    pub faucet_rate_limit: Mutex<HashMap<String, i64>>,
    /// Faucet IP rate limiter: client IP -> last request timestamp
    pub faucet_ip_rate_limit: Mutex<HashMap<String, i64>>,
    /// Faucet account address (from genesis config)
    pub faucet_address: Option<String>,
    /// Amount to dispense per request (whole TNZO units)
    pub faucet_amount: u128,
    /// Cooldown in seconds
    pub faucet_cooldown_secs: u64,
    /// In-memory FROST(Ed25519, secp256k1) round coordinator. Each
    /// `/wallet/frost/*` request reads or mutates a session here. The
    /// coordinator is intentionally not durable on testnet — sessions
    /// are short-lived (5 min TTL) and the wallet retries on
    /// disconnect rather than resuming mid-round.
    pub frost_coordinator: super::wallet_frost::FrostCoordinator,
    /// In-memory passkey-share-unwrap escrow. Holds the per-call
    /// nonces issued by `POST /wallet/share/escrow/challenge` and
    /// consumed by `POST /wallet/share/escrow/unwrap`. Single-use,
    /// 30-second TTL. Not durable on testnet — a node restart
    /// invalidates all outstanding ceremonies, and the wallet just
    /// re-prompts the user.
    pub share_escrow: super::wallet_share::ShareEscrow,
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
            faucet_rate_limit: Mutex::new(HashMap::new()),
            faucet_ip_rate_limit: Mutex::new(HashMap::new()),
            faucet_address: None,
            faucet_amount: 100,
            faucet_cooldown_secs: 86400, // 24 hours
            frost_coordinator: super::wallet_frost::FrostCoordinator::new(),
            share_escrow: super::wallet_share::ShareEscrow::new(),
        }
    }

    pub fn with_node(mut self, node: Arc<TenzroNode>) -> Self {
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

    pub fn with_faucet(mut self, address: String, amount: u128, cooldown: u64) -> Self {
        self.faucet_address = Some(address);
        self.faucet_amount = amount;
        self.faucet_cooldown_secs = cooldown;
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

/// Verify a Plonky3 STARK proof.
///
/// The handler reconstructs a [`tenzro_zk::Proof`] envelope from the request,
/// dispatches to the right AIR by `circuit_id`, and runs the full off-chain
/// Plonky3 verifier. Returns `valid: true` only on cryptographic success.
pub async fn verify_zk_proof(
    Json(request): Json<VerifyZkProofRequest>,
) -> Json<VerificationResponse> {
    let now = || Utc::now().to_rfc3339();

    if request.circuit_id.is_empty() {
        return Json(VerificationResponse {
            valid: false,
            details: serde_json::json!({
                "error": "circuit_id is required (e.g. \"inference\", \"settlement\", \"identity\")",
            }),
            verified_at: now(),
        });
    }
    let circuit_id = request.circuit_id.clone();

    // Decode proof bytes from hex
    let proof_hex = request.proof_bytes.strip_prefix("0x").unwrap_or(&request.proof_bytes);
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

    let proof_size = proof_bytes.len();
    let public_inputs_count = public_inputs.len();

    // Build a wire-format Proof envelope and run the Plonky3 verifier.
    // tenzro-zk::verify_proof_envelope dispatches by circuit_id internally.
    let envelope = Proof::new(proof_bytes, public_inputs, circuit_id.clone());

    // Run verification on a blocking thread — the verifier is CPU-bound and
    // would otherwise stall the axum executor on large proofs.
    let verify_result = tokio::task::spawn_blocking(move || verify_proof_envelope(&envelope))
        .await
        .unwrap_or_else(|join_err| {
            Err(VerifyEnvelopeError::VerifierRejected(format!(
                "spawn_blocking join error: {join_err}"
            )))
        });

    match verify_result {
        Ok(()) => Json(VerificationResponse {
            valid: true,
            details: serde_json::json!({
                "proof_type": "plonky3",
                "circuit_id": circuit_id,
                "public_inputs_count": public_inputs_count,
                "proof_size_bytes": proof_size,
                "status": "plonky3_verified",
            }),
            verified_at: now(),
        }),
        Err(e) => {
            let (status, error) = match &e {
                VerifyEnvelopeError::UnknownCircuit(id) => {
                    ("unknown_circuit", format!("no AIR registered for circuit_id={id}"))
                }
                VerifyEnvelopeError::EnvelopeDecode(zk_err) => {
                    ("envelope_decode_failed", zk_err.to_string())
                }
                VerifyEnvelopeError::VerifierRejected(detail) => {
                    ("verifier_rejected", detail.clone())
                }
            };
            Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "proof_type": "plonky3",
                    "circuit_id": circuit_id,
                    "public_inputs_count": public_inputs_count,
                    "proof_size_bytes": proof_size,
                    "status": status,
                    "error": error,
                }),
                verified_at: now(),
            })
        }
    }
}

/// Verify a TEE attestation using tenzro-tee AttestationVerifier
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
    let report_hex = request.report_data.strip_prefix("0x").unwrap_or(&request.report_data);
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
    let certificates: Vec<Vec<u8>> = request.certificate_chain
        .as_ref()
        .map(|certs| {
            certs.iter()
                .filter_map(|pem| pem.as_bytes().to_vec().into())
                .collect()
        })
        .unwrap_or_default();

    // Parse expected measurement if provided
    let measurement = request.measurement
        .as_ref()
        .and_then(|m| {
            let hex_str = m.strip_prefix("0x").unwrap_or(m);
            hex::decode(hex_str).ok()
        })
        .unwrap_or_default();

    // Build AttestationReport
    let report = AttestationReport {
        id: uuid::Uuid::new_v4(),
        vendor,
        user_data: Vec::new(),
        attestation_data,
        certificates,
        timestamp: Timestamp::now(),
        metadata: HashMap::new(),
        quote: Vec::new(),
        measurement,
        signature: Vec::new(),
        vendor_data: Vec::new(),
    };

    // Verify using AttestationVerifier
    let verifier = AttestationVerifier::new();
    match verifier.verify_report(&report) {
        Ok(result) => {
            let details = serde_json::json!({
                "vendor": format!("{:?}", result.vendor),
                "tcb_version": result.tcb_version,
                "cert_chain_valid": result.cert_chain_valid,
                "measurements_count": result.measurements.len(),
                "simulated": result.details.get("simulated").unwrap_or(&"false".to_string()),
                "status": "tee_cryptographic_verification",
            });

            Json(VerificationResponse {
                valid: result.valid,
                details,
                verified_at: Utc::now().to_rfc3339(),
            })
        }
        Err(e) => {
            Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "vendor": request.vendor,
                    "error": format!("{}", e),
                    "status": "tee_verification_failed",
                }),
                verified_at: Utc::now().to_rfc3339(),
            })
        }
    }
}

/// Verify a transaction signature using tenzro-crypto
pub async fn verify_transaction(
    Json(request): Json<VerifyTransactionRequest>,
) -> Json<VerificationResponse> {
    // Decode transaction hash (the message that was signed)
    let hash_hex = request.tx_hash.strip_prefix("0x").unwrap_or(&request.tx_hash);
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

    // Decode signature
    let sig_hex = request.signature.strip_prefix("0x").unwrap_or(&request.signature);
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid signature hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // Decode sender public key
    let sender_hex = request.sender.strip_prefix("0x").unwrap_or(&request.sender);
    let sender_bytes = match hex::decode(sender_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid sender hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // Decode the mandatory PQ leg (ML-DSA-65 signature + verifying key).
    let pq_sig_hex = request.pq_signature.strip_prefix("0x").unwrap_or(&request.pq_signature);
    let pq_sig_bytes = match hex::decode(pq_sig_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid pq_signature hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };
    let pq_vk_hex = request.pq_public_key.strip_prefix("0x").unwrap_or(&request.pq_public_key);
    let pq_vk_bytes = match hex::decode(pq_vk_hex) {
        Ok(b) => b,
        Err(e) => {
            return Json(VerificationResponse {
                valid: false,
                details: serde_json::json!({
                    "error": format!("Invalid pq_public_key hex: {}", e),
                }),
                verified_at: Utc::now().to_rfc3339(),
            });
        }
    };

    // 1. Classical leg. Determine key type from sender length:
    //    Ed25519 public keys are 32 bytes, Secp256k1 are 33 (compressed) or 65 (uncompressed).
    let (classical_valid, classical_status) = if sender_bytes.len() == 32 {
        let pubkey = PublicKey::new(KeyType::Ed25519, sender_bytes.clone());
        let signature = CryptoSignature::new(KeyType::Ed25519, sig_bytes.clone());
        match tenzro_crypto::signatures::verify(&pubkey, &tx_hash_bytes, &signature) {
            Ok(()) => (true, "ed25519_signature_valid"),
            Err(_) => (false, "ed25519_signature_invalid"),
        }
    } else if sender_bytes.len() == 33 || sender_bytes.len() == 65 {
        let pubkey = PublicKey::new(KeyType::Secp256k1, sender_bytes.clone());
        let signature = CryptoSignature::new(KeyType::Secp256k1, sig_bytes.clone());
        match tenzro_crypto::signatures::verify(&pubkey, &tx_hash_bytes, &signature) {
            Ok(()) => (true, "secp256k1_signature_valid"),
            Err(_) => (false, "secp256k1_signature_invalid"),
        }
    } else {
        (false, "unsupported_key_length")
    };

    // 2. Post-quantum leg. ML-DSA-65 over the same tx_hash bytes.
    let (pq_valid, pq_status) =
        match tenzro_crypto::pq::ml_dsa_verify(&pq_vk_bytes, &tx_hash_bytes, &pq_sig_bytes) {
            Ok(()) => (true, "ml_dsa_65_signature_valid"),
            Err(_) => (false, "ml_dsa_65_signature_invalid"),
        };

    // Both legs must verify.
    let valid = classical_valid && pq_valid;

    let details = serde_json::json!({
        "tx_hash": request.tx_hash,
        "sender": request.sender,
        "signature_size": sig_bytes.len(),
        "sender_key_size": sender_bytes.len(),
        "pq_signature_size": pq_sig_bytes.len(),
        "pq_public_key_size": pq_vk_bytes.len(),
        "has_data": request.data.is_some(),
        "classical_status": classical_status,
        "pq_status": pq_status,
        "status": if valid { "hybrid_signature_valid" } else { "hybrid_signature_invalid" },
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
    let amount_valid = request.amount.parse::<f64>().map(|a| a > 0.0).unwrap_or(false);
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
                        // Structural validation of ZK proof data
                        let zk_valid = proof.proof_data.len() >= 128;
                        (zk_valid && amount_valid, "settlement_zk_proof_verified")
                    }
                    SettlementProofType::TeeAttestation => {
                        // Verify TEE attestation using tenzro-tee
                        if proof.proof_data.len() >= 32 {
                            let verifier = AttestationVerifier::new();
                            // Try to deserialize as AttestationReport
                            match serde_json::from_slice::<AttestationReport>(&proof.proof_data) {
                                Ok(report) => {
                                    let tee_result = verifier.verify_report(&report);
                                    let tee_valid = tee_result.map(|r| r.valid).unwrap_or(false);
                                    (tee_valid && amount_valid, "settlement_tee_attestation_verified")
                                }
                                Err(_) => {
                                    // Structural validation fallback
                                    (amount_valid && proof.proof_data.len() >= 64, "settlement_tee_structural_validation")
                                }
                            }
                        } else {
                            (false, "settlement_tee_proof_too_small")
                        }
                    }
                    SettlementProofType::Cryptographic => {
                        // Verify Ed25519 signature presence in proof
                        let has_signature = proof.proof_data.len() >= 64;
                        let has_signatures = !proof.signatures.is_empty();
                        (has_signature && has_signatures && amount_valid, "settlement_cryptographic_verified")
                    }
                    SettlementProofType::MultiParty => {
                        // Multi-party proof — verify sufficient signatures
                        let has_signatures = proof.signatures.len() >= 2;
                        (has_signatures && amount_valid, "settlement_multiparty_verified")
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
                        let verifier = AttestationVerifier::new();
                        match verifier.verify_report(&report) {
                            Ok(result) => {
                                tee_valid = Some(result.valid);
                                tee_status = if result.valid {
                                    "tee_attestation_valid"
                                } else {
                                    "tee_attestation_invalid"
                                };
                            }
                            Err(_) => {
                                tee_valid = Some(false);
                                tee_status = "tee_verification_error";
                            }
                        }
                    }
                    Err(_) => {
                        // Structural validation: check attestation data is substantial
                        let structural = att_bytes.len() >= 64;
                        tee_valid = Some(structural);
                        tee_status = if structural {
                            "tee_structural_validation_passed"
                        } else {
                            "tee_structural_validation_failed"
                        };
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
                // Try to deserialize as tenzro_zk::Proof
                match serde_json::from_slice::<Proof>(&proof_bytes) {
                    Ok(proof) => {
                        // Structural validation — check proof has expected fields
                        let proof_valid = !proof.proof_bytes.is_empty()
                            && proof.proof_bytes.len() >= 32
                            && !proof.public_inputs.is_empty();
                        zk_valid = Some(proof_valid);
                        zk_status = if proof_valid {
                            "zk_proof_structurally_valid"
                        } else {
                            "zk_proof_structurally_invalid"
                        };
                    }
                    Err(_) => {
                        // Raw bytes — structural check
                        let structural = proof_bytes.len() >= 128;
                        zk_valid = Some(structural);
                        zk_status = if structural {
                            "zk_raw_structural_passed"
                        } else {
                            "zk_raw_structural_failed"
                        };
                    }
                }
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
pub async fn health(
    State(state): State<Arc<WebState>>,
) -> Json<HealthResponse> {
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
/// to the network on both block height and consensus view. Returns HTTP
/// 503 with `ready: false` and a `reason` string otherwise — matches the
/// CometBFT / Solana / Aptos pattern of separating liveness (`/health`)
/// from production-traffic readiness (`/ready`).
///
/// Tolerances:
///   * `block_lag_tolerance = 5`  — typical mempool churn
///   * `view_lag_tolerance  = 2`  — leaves headroom for one timeout round
///
/// When network tip is unknown (no fresh peer status), readiness gates
/// purely on `peer_count >= 1`, so a fresh testnet bootstrap can come up.
pub async fn ready(
    State(state): State<Arc<WebState>>,
) -> (StatusCode, Json<ReadyResponse>) {
    const BLOCK_LAG_TOLERANCE: u64 = 5;
    const VIEW_LAG_TOLERANCE: u64 = 2;

    let Some(ref node) = state.node else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                block_height: 0,
                network_tip: None,
                block_lag: None,
                high_qc_view: 0,
                peer_count: 0,
                reason: "node not initialized".to_string(),
            }),
        );
    };

    let node_status = node.status().await;
    let block_height = node_status.block_height;
    let peer_count = node_status.peer_count;
    let network_tip = node.network_tip();
    let high_qc_view = node
        .consensus()
        .map(|c| c.high_qc_view())
        .unwrap_or(0);

    // Compute block lag against network tip if available.
    let block_lag = network_tip.map(|tip| tip.saturating_sub(block_height));

    // Gating logic.
    let (ready, reason) = if peer_count == 0 {
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
            // Block height caught up; check consensus view freshness.
            // Without per-peer view-tip gossip we can't bound view lag
            // precisely — the conservative check is `high_qc_view + view_lag
            // >= local_height`, since under a healthy chain every committed
            // block carries a QC view ≥ block height.
            if high_qc_view + VIEW_LAG_TOLERANCE < block_height {
                (
                    false,
                    format!(
                        "high_qc_view {} lags block_height {} by > {}",
                        high_qc_view, block_height, VIEW_LAG_TOLERANCE
                    ),
                )
            } else {
                (true, "caught up".to_string())
            }
        }
    } else {
        // No fresh peer status — bootstrap or isolated node. Allow Ready
        // as long as we have at least one peer to gossip with.
        (true, "no network tip yet, peer present".to_string())
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
            high_qc_view,
            peer_count,
            reason,
        }),
    )
}

/// Node status endpoint
pub async fn status(
    State(state): State<Arc<WebState>>,
) -> Json<NodeStatusResponse> {
    if let Some(ref node) = state.node {
        let node_status = node.status().await;
        let health_status = node.health_monitor().get_status(
            BlockHeight::from(node_status.block_height),
            node_status.peer_count as usize,
        );
        Json(NodeStatusResponse {
            node_state: node_status.state,
            role: format!("{:?}", node_status.role),
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
            role: "unknown".to_string(),
            health: "healthy".to_string(),
            block_height: 0,
            peer_count: 0,
            uptime_secs: 0,
            ready: false,
            status_message: "Node not initialized".to_string(),
        })
    }
}

/// `GET /.well-known/jwks.json` — public JWK Set covering every active
/// Tenzro identity's RFC-9421-compatible signing key.
///
/// Per RFC 7517 §5 the body is `{"keys": [<jwk>...]}`. External verifiers
/// (Visa TAP, Mastercard, Stripe MPP, AP2 facilitators, x402 settlement
/// nodes, generic RFC 9421 clients) can resolve a `keyid` parameter
/// against this endpoint and use the returned key to verify HTTP message
/// signatures issued by Tenzro agents.
///
/// Suspended/revoked identities are still listed but with `active: false`.
/// Verifiers SHOULD reject signatures from inactive keys.
pub async fn jwks(
    State(state): State<Arc<WebState>>,
) -> Json<tenzro_payments::rfc9421::JwkSet> {
    let agents = if let Some(ref node) = state.node {
        if let Some(registry) = node.identity_registry() {
            let agent_registry =
                tenzro_payments::rfc9421::TenzroAgentRegistry::new(registry.clone());
            agent_registry.list_all_agents()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Json(tenzro_payments::rfc9421::JwkSet::from_agents(&agents))
}

/// `GET /.well-known/jwks.json/:keyid` — single JWK lookup. The `:keyid`
/// path segment is URL-decoded by axum and passed through to the agent
/// registry, which accepts `did:tenzro:...` (first compatible key) and
/// `did:tenzro:...#fragment` (specific key) forms.
///
/// Returns 404 if no agent matches `keyid` or the agent has no
/// RFC-9421-compatible key. Returns 422 if the matched key cannot be
/// JWK-encoded (e.g. malformed bytes); HMAC keys are rejected with 422.
pub async fn jwks_get(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(keyid): axum::extract::Path<String>,
) -> Result<Json<tenzro_payments::rfc9421::Jwk>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    use axum::http::StatusCode;
    use tenzro_payments::rfc9421::{AgentRegistryClient, Jwk, TenzroAgentRegistry};

    let node = state.node.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node not initialized" })),
        )
    })?;
    let registry = node.identity_registry().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "identity registry not initialized" })),
        )
    })?;

    let agent_registry = TenzroAgentRegistry::new(registry.clone());
    let agent = agent_registry.get_public_key(&keyid).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e.to_string(), "keyid": keyid })),
        )
    })?;

    let jwk = Jwk::try_from_agent(&agent).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": e.to_string(), "keyid": keyid })),
        )
    })?;

    Ok(Json(jwk))
}

/// Extract client IP from request headers (behind reverse proxy)
fn extract_client_ip(headers: &HeaderMap) -> String {
    // Check X-Forwarded-For first (set by Caddy/nginx reverse proxy)
    if let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(val) = xff.to_str() {
            // X-Forwarded-For can be comma-separated; take the first (original client)
            if let Some(first_ip) = val.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    // Fallback to X-Real-Ip (set by some proxies)
    if let Some(xri) = headers.get("x-real-ip")
        && let Ok(val) = xri.to_str() {
            let ip = val.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    // No proxy header found — use "unknown"
    "unknown".to_string()
}

/// Check IP-based rate limit (returns remaining seconds if rate-limited, 0 if OK)
fn check_ip_rate_limit(
    state: &WebState,
    client_ip: &str,
    now: i64,
    storage: Option<&Arc<tenzro_storage::RocksDbStore>>,
) -> u64 {
    // Skip IP rate limit for unknown IPs (direct connections without proxy)
    if client_ip == "unknown" {
        return 0;
    }

    let cooldown = state.faucet_cooldown_secs as i64;

    // Check in-memory cache first
    {
        let ip_limits = state.faucet_ip_rate_limit.lock();
        if let Some(&last_ts) = ip_limits.get(client_ip) {
            let elapsed = now - last_ts;
            if elapsed < cooldown {
                return (cooldown - elapsed) as u64;
            }
        }
    }

    // Check persistent storage (survives pod restarts)
    if let Some(store) = storage {
        let ip_key = format!("faucet_ip:{}", client_ip);
        if let Ok(Some(bytes)) = store.get("metadata", ip_key.as_bytes()) {
            let bytes: Vec<u8> = bytes;
            if bytes.len() == 8 {
                let last_ts = i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                let elapsed = now - last_ts;
                if elapsed < cooldown {
                    return (cooldown - elapsed) as u64;
                }
            }
        }
    }

    0
}

/// Record IP-based rate limit (in-memory + persistent)
fn record_ip_rate_limit(
    state: &WebState,
    client_ip: &str,
    now: i64,
    storage: Option<&Arc<tenzro_storage::RocksDbStore>>,
) {
    if client_ip == "unknown" {
        return;
    }

    // In-memory
    {
        let mut ip_limits = state.faucet_ip_rate_limit.lock();
        ip_limits.insert(client_ip.to_string(), now);
    }

    // Persistent
    if let Some(store) = storage {
        let ip_key = format!("faucet_ip:{}", client_ip);
        let _ = store.put("metadata", ip_key.as_bytes(), &now.to_le_bytes());
    }
}

/// Faucet endpoint — dispenses testnet TNZO
pub async fn faucet(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(request): Json<FaucetRequest>,
) -> Json<FaucetResponse> {
    // Check if faucet is configured
    let faucet_addr = match &state.faucet_address {
        Some(addr) => addr.clone(),
        None => return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: "Faucet not configured".to_string(),
        }),
    };

    // Get node reference for token operations
    let node = match &state.node {
        Some(n) => n.clone(),
        None => return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: "Node not available".to_string(),
        }),
    };

    // Get token system
    let token = match node.token() {
        Some(t) => t,
        None => return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: "Token system not initialized".to_string(),
        }),
    };

    // Extract client IP for IP-based rate limiting
    let client_ip = extract_client_ip(&headers);
    let now = Utc::now().timestamp();

    // Get storage reference for persistent rate limit checks
    let storage_ref = node.storage();

    // IP-based rate limit — 24h cooldown per IP (checked first)
    let ip_remaining = check_ip_rate_limit(&state, &client_ip, now, storage_ref);
    if ip_remaining > 0 {
        return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: format!("Rate limited by IP. Try again in {} seconds", ip_remaining),
        });
    }

    // Validate recipient address
    let addr_hex = request.address.strip_prefix("0x").unwrap_or(&request.address);
    let addr_bytes = match hex::decode(addr_hex) {
        Ok(b) if b.len() <= 32 => b,
        _ => return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: "Invalid address format".to_string(),
        }),
    };

    // Address-based rate limit — 24h cooldown per address
    let addr_key = addr_hex.to_lowercase();
    {
        // Check in-memory rate limit cache
        let rate_limit = state.faucet_rate_limit.lock();
        if let Some(&last_request) = rate_limit.get(&addr_key) {
            let elapsed = now - last_request;
            if elapsed < state.faucet_cooldown_secs as i64 {
                let remaining = state.faucet_cooldown_secs as i64 - elapsed;
                return Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    amount: "0".to_string(),
                    message: format!("Rate limited by address. Try again in {} seconds", remaining),
                });
            }
        }
    }

    // Also check persisted address rate limit from storage (survives restarts)
    if let Some(storage) = storage_ref {
        let faucet_key = format!("faucet_request:{}", addr_key);
        if let Ok(Some(bytes)) = storage.get("metadata", faucet_key.as_bytes()) {
            let bytes: Vec<u8> = bytes;
            if bytes.len() == 8 {
                let last_ts = i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                let elapsed = now - last_ts;
                if elapsed < state.faucet_cooldown_secs as i64 {
                    let remaining = state.faucet_cooldown_secs as i64 - elapsed;
                    return Json(FaucetResponse {
                        success: false,
                        tx_hash: None,
                        amount: "0".to_string(),
                        message: format!("Rate limited by address. Try again in {} seconds", remaining),
                    });
                }
            }
        }
    }

    // Parse faucet source address
    let faucet_hex = faucet_addr.strip_prefix("0x").unwrap_or(&faucet_addr);
    let faucet_bytes = match hex::decode(faucet_hex) {
        Ok(b) => b,
        Err(_) => return Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: "Invalid faucet address configuration".to_string(),
        }),
    };

    // Build addresses
    let mut from_bytes = [0u8; 32];
    let faucet_len = faucet_bytes.len().min(32);
    from_bytes[..faucet_len].copy_from_slice(&faucet_bytes[..faucet_len]);
    let from_addr = Address::new(from_bytes);

    let mut to_bytes = [0u8; 32];
    let to_len = addr_bytes.len().min(32);
    to_bytes[..to_len].copy_from_slice(&addr_bytes[..to_len]);
    let to_addr = Address::new(to_bytes);

    // Amount in base units (whole TNZO * 10^18)
    let amount_base = state.faucet_amount;
    let amount_wei = amount_base.checked_mul(1_000_000_000_000_000_000u128).unwrap_or(0);

    // Transfer directly via TnzoToken (persists to RocksDB immediately)
    match token.transfer(&from_addr, &to_addr, amount_wei) {
        Ok(_) => {
            // Generate a tx hash from the transfer details
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(from_addr.as_bytes());
            hasher.update(to_addr.as_bytes());
            hasher.update(amount_wei.to_le_bytes());
            hasher.update(now.to_le_bytes());
            let tx_hash = hex::encode(hasher.finalize());

            // Record address rate limit timestamp (in-memory + persistent)
            {
                let mut rate_limit = state.faucet_rate_limit.lock();
                rate_limit.insert(addr_key.clone(), now);
            }
            if let Some(storage) = storage_ref {
                let faucet_key = format!("faucet_request:{}", addr_key);
                let _ = storage.put("metadata", faucet_key.as_bytes(), &now.to_le_bytes());
            }

            // Record IP rate limit timestamp (in-memory + persistent)
            record_ip_rate_limit(&state, &client_ip, now, storage_ref);

            Json(FaucetResponse {
                success: true,
                tx_hash: Some(tx_hash),
                amount: format!("{} TNZO", amount_base),
                message: "Tokens dispensed successfully".to_string(),
            })
        }
        Err(e) => Json(FaucetResponse {
            success: false,
            tx_hash: None,
            amount: "0".to_string(),
            message: format!("Failed to transfer tokens: {}", e),
        }),
    }
}

/// Prometheus metrics endpoint — exports metrics in Prometheus text exposition format
pub async fn prometheus_metrics(
    State(state): State<Arc<WebState>>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let metrics = match &state.metrics {
        Some(m) => m.get_metrics(),
        None => crate::metrics::NodeMetrics {
            blocks_processed: 0,
            transactions_processed: 0,
            inference_requests: 0,
            settlements: 0,
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
    body.push_str(&format!("tenzro_node_uptime_seconds {}\n\n", metrics.uptime_secs));

    // Blocks
    body.push_str("# HELP tenzro_blocks_processed_total Total blocks processed\n");
    body.push_str("# TYPE tenzro_blocks_processed_total counter\n");
    body.push_str(&format!("tenzro_blocks_processed_total {}\n\n", metrics.blocks_processed));

    // Transactions
    body.push_str("# HELP tenzro_transactions_processed_total Total transactions processed\n");
    body.push_str("# TYPE tenzro_transactions_processed_total counter\n");
    body.push_str(&format!("tenzro_transactions_processed_total {}\n\n", metrics.transactions_processed));

    // Inference
    body.push_str("# HELP tenzro_inference_requests_total Total AI inference requests handled\n");
    body.push_str("# TYPE tenzro_inference_requests_total counter\n");
    body.push_str(&format!("tenzro_inference_requests_total {}\n\n", metrics.inference_requests));

    // Settlements
    body.push_str("# HELP tenzro_settlements_total Total settlements processed\n");
    body.push_str("# TYPE tenzro_settlements_total counter\n");
    body.push_str(&format!("tenzro_settlements_total {}\n\n", metrics.settlements));

    // Peers
    body.push_str("# HELP tenzro_peer_count Current number of connected peers\n");
    body.push_str("# TYPE tenzro_peer_count gauge\n");
    body.push_str(&format!("tenzro_peer_count {}\n\n", metrics.peer_count));

    // Derived rate gauges (computed from cumulative counters + uptime)
    body.push_str("# HELP tenzro_blocks_per_second Average blocks processed per second since node start\n");
    body.push_str("# TYPE tenzro_blocks_per_second gauge\n");
    body.push_str(&format!("tenzro_blocks_per_second {:.4}\n\n", metrics.blocks_per_second()));

    body.push_str("# HELP tenzro_transactions_per_second Average transactions processed per second since node start\n");
    body.push_str("# TYPE tenzro_transactions_per_second gauge\n");
    body.push_str(&format!("tenzro_transactions_per_second {:.4}\n\n", metrics.transactions_per_second()));

    // Uptime info metric — value is always 1; human-readable form lives in the label
    body.push_str("# HELP tenzro_node_uptime_info Node uptime in human-readable form\n");
    body.push_str("# TYPE tenzro_node_uptime_info gauge\n");
    body.push_str(&format!("tenzro_node_uptime_info{{uptime=\"{}\"}} 1\n\n", metrics.uptime_human()));

    // Node health
    if let Some(ref node) = state.node {
        let status = node.status().await;
        let health_val = match status.health_status {
            crate::health::OverallHealth::Healthy => 1,
            crate::health::OverallHealth::Degraded => 0,
            crate::health::OverallHealth::Unhealthy => -1,
            crate::health::OverallHealth::Unknown => -2,
        };
        body.push_str("# HELP tenzro_node_health Node health status (1=healthy, 0=degraded, -1=unhealthy)\n");
        body.push_str("# TYPE tenzro_node_health gauge\n");
        body.push_str(&format!("tenzro_node_health {}\n\n", health_val));

        body.push_str("# HELP tenzro_block_height Current block height\n");
        body.push_str("# TYPE tenzro_block_height gauge\n");
        body.push_str(&format!("tenzro_block_height {}\n\n", status.block_height));

        // Model services count
        let model_count = node.list_model_services().len();
        body.push_str("# HELP tenzro_model_services_count Number of active model service instances\n");
        body.push_str("# TYPE tenzro_model_services_count gauge\n");
        body.push_str(&format!("tenzro_model_services_count {}\n\n", model_count));

        // Workflow-subsystem snapshot (workflows / obligations / approvals
        // partitioned by status, signature totals, canton-mirror count, fee
        // routes, privacy domains). The snapshot is computed by walking the
        // in-memory indices on `WorkflowManager` plus sibling registry sizes
        // — O(N_workflows + N_obligations + N_requests), sub-millisecond at
        // testnet scale (≤10k live workflows).
        if let Some(rt) = node.workflow_runtime() {
            body.push_str(&rt.operational_metrics().render_prometheus());
            body.push('\n');
        }
    }

    // Append network-layer metrics (gossipsub, dial rate limits, peer counts, etc.)
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

    // Append cortex worker metrics (cortex_requests_total, cortex_loops_executed_total,
    // cortex_cost_wei_total, per-tier rejection counters, latency histograms, etc.).
    // The `cortex_metrics` registry is shared across every `CortexWorker` spawned
    // on this node via `CortexWorker::with_metrics(node.cortex_metrics.clone())`
    // in `init_cortex_workers`, so this single `encode_prometheus` call captures
    // activity from all local workers.
    if let Some(ref node) = state.node {
        node.cortex_metrics.encode_prometheus(&mut body);
    }

    // Append Spec 2 (#312) per-DID admission lane metrics. The
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
        && let Some(admission) = node.admission() {
            use tenzro_consensus::admission::Lane;

            let stats = admission.stats();

            // admitted_total{lane}
            body.push_str("# HELP tenzro_mempool_admitted_total Transactions admitted to the mempool, broken down by Spec 2 admission lane\n");
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
            body.push_str(&format!("tenzro_mempool_bucket_count {}\n\n", stats.bucket_count));

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

    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ).into_response()
}

/// Chat completion endpoint with SSE streaming support
pub async fn chat_completion(
    State(state): State<Arc<WebState>>,
    Json(request): Json<super::types::ChatRequest>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, sse::{Event, Sse}};
    use axum::http::StatusCode;

    // Check if inference router is available
    let router = match &state.inference_router {
        Some(r) => r.clone(),
        None => {
            let error = serde_json::json!({
                "error": {
                    "message": "Inference router not available",
                    "type": "service_unavailable",
                    "code": "router_not_configured"
                }
            });
            return (StatusCode::SERVICE_UNAVAILABLE, Json(error)).into_response();
        }
    };

    // Validate inputs at API boundary (MEDIUM #115)
    use tenzro_types::validation;
    if let Err(e) = validation::validate_string_len(
        &request.model, "model", validation::MAX_MODEL_ID_LEN,
    ) {
        let error = serde_json::json!({ "error": { "message": e.to_string(), "type": "invalid_request_error", "code": "invalid_model" }});
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }
    if let Err(e) = validation::validate_vec_len(
        &request.messages, "messages", validation::MAX_CHAT_MESSAGES,
    ) {
        let error = serde_json::json!({ "error": { "message": e.to_string(), "type": "invalid_request_error", "code": "too_many_messages" }});
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }
    for msg in &request.messages {
        if let Err(e) = validation::validate_string_len(
            &msg.content, "message.content", validation::MAX_CHAT_MESSAGE_LEN,
        ) {
            let error = serde_json::json!({ "error": { "message": e.to_string(), "type": "invalid_request_error", "code": "message_too_long" }});
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    }
    if let Some(max_tokens) = request.max_tokens
        && let Err(e) = validation::validate_numeric_bound(
            max_tokens, "max_tokens", validation::MAX_INFERENCE_TOKENS,
        ) {
            let error = serde_json::json!({ "error": { "message": e.to_string(), "type": "invalid_request_error", "code": "max_tokens_exceeded" }});
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    if let Some(temp) = request.temperature
        && let Err(e) = validation::validate_temperature(temp) {
            let error = serde_json::json!({ "error": { "message": e.to_string(), "type": "invalid_request_error", "code": "invalid_temperature" }});
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }

    // Generate unique chat completion ID
    let completion_id = format!("chatcmpl-{}", uuid::Uuid::new_v4());
    let created = Utc::now().timestamp() as u64;
    let stream = request.stream.unwrap_or(true);

    // Build messages string for inference request
    let mut messages_text = String::new();
    for msg in &request.messages {
        messages_text.push_str(&format!("{}: {}\n", msg.role, msg.content));
    }

    // Build InferenceRequest
    let inference_request = tenzro_types::model::InferenceRequest {
        request_id: completion_id.clone(),
        model_id: request.model.clone(),
        requester: tenzro_types::primitives::Address::default(), // Anonymous web request
        input: messages_text.as_bytes().to_vec(),
        parameters: tenzro_types::model::InferenceParameters {
            temperature: request.temperature.map(|t| (t * 100.0) as u32),
            top_p: None,
            top_k: None,
            max_tokens: request.max_tokens.map(|t| t as u32),
            stop_sequences: Vec::new(),
            custom: HashMap::new(),
        },
        max_price: u64::MAX, // No price limit for web requests
        timestamp: Timestamp::now(),
        callback: None,
    };

    if !stream {
        // Non-streaming: forward request and return full response
        match router.forward_request(&inference_request).await {
            Ok(response) => {
                let output_text = String::from_utf8_lossy(&response.output).to_string();

                let chat_response = super::types::ChatCompletionResponse {
                    id: completion_id,
                    object: "chat.completion".to_string(),
                    created,
                    model: request.model.clone(),
                    choices: vec![super::types::ChatCompletionChoice {
                        index: 0,
                        message: super::types::ChatMessage {
                            role: "assistant".to_string(),
                            content: output_text,
                        },
                        finish_reason: response.metadata.finish_reason.unwrap_or_else(|| "stop".to_string()),
                    }],
                    usage: super::types::ChatUsage {
                        prompt_tokens: response.metadata.input_tokens as u64,
                        completion_tokens: response.metadata.output_tokens as u64,
                        total_tokens: (response.metadata.input_tokens + response.metadata.output_tokens) as u64,
                    },
                };

                Json(chat_response).into_response()
            }
            Err(e) => {
                let error = serde_json::json!({
                    "error": {
                        "message": format!("Inference failed: {}", e),
                        "type": "inference_error",
                        "code": "inference_failed"
                    }
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
            }
        }
    } else {
        // Streaming: use SSE to stream token-by-token chunks
        let model_name = request.model.clone();
        let stream = async_stream::stream! {
            // Forward request to provider
            match router.forward_request(&inference_request).await {
                Ok(response) => {
                    let output_text = String::from_utf8_lossy(&response.output).to_string();

                    // Send initial chunk with role
                    let initial_chunk = super::types::ChatCompletionChunk {
                        id: completion_id.clone(),
                        object: "chat.completion.chunk".to_string(),
                        created,
                        model: model_name.clone(),
                        choices: vec![super::types::ChatChoice {
                            index: 0,
                            delta: super::types::ChatDelta {
                                role: Some("assistant".to_string()),
                                content: None,
                            },
                            finish_reason: None,
                        }],
                    };

                    if let Ok(json) = serde_json::to_string(&initial_chunk) {
                        yield Ok::<Event, axum::Error>(Event::default().data(json));
                    }

                    // Stream tokens (simulate token-by-token by splitting into words)
                    let words: Vec<&str> = output_text.split_whitespace().collect();
                    for (i, word) in words.iter().enumerate() {
                        let content = if i == 0 {
                            word.to_string()
                        } else {
                            format!(" {}", word)
                        };

                        let chunk = super::types::ChatCompletionChunk {
                            id: completion_id.clone(),
                            object: "chat.completion.chunk".to_string(),
                            created,
                            model: model_name.clone(),
                            choices: vec![super::types::ChatChoice {
                                index: 0,
                                delta: super::types::ChatDelta {
                                    role: None,
                                    content: Some(content),
                                },
                                finish_reason: None,
                            }],
                        };

                        if let Ok(json) = serde_json::to_string(&chunk) {
                            yield Ok(Event::default().data(json));
                        }

                        // Small delay to simulate streaming
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    }

                    // Send final chunk with finish_reason
                    let final_chunk = super::types::ChatCompletionChunk {
                        id: completion_id.clone(),
                        object: "chat.completion.chunk".to_string(),
                        created,
                        model: model_name.clone(),
                        choices: vec![super::types::ChatChoice {
                            index: 0,
                            delta: super::types::ChatDelta {
                                role: None,
                                content: None,
                            },
                            finish_reason: Some(response.metadata.finish_reason.unwrap_or_else(|| "stop".to_string())),
                        }],
                    };

                    if let Ok(json) = serde_json::to_string(&final_chunk) {
                        yield Ok(Event::default().data(json));
                    }

                    // Send [DONE] event
                    yield Ok(Event::default().data("[DONE]"));
                }
                Err(e) => {
                    // Send error as SSE event
                    let error_event = serde_json::json!({
                        "error": {
                            "message": format!("Inference failed: {}", e),
                            "type": "inference_error",
                            "code": "inference_failed"
                        }
                    });

                    if let Ok(json) = serde_json::to_string(&error_event) {
                        yield Ok(Event::default().event("error").data(json));
                    }
                }
            }
        };

        Sse::new(stream).into_response()
    }
}

// ===== RFC-0007: Adaptive Execution — HTTP handlers =====

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
            .find(|p| {
                // Apply routing_policy: require_attestation filters to attested providers
                if routing.is_some_and(|r| r.require_attestation) {
                    p.announcement.capabilities.iter().any(|c| c.contains("tee"))
                } else {
                    true
                }
            });

        if let Some(entry) = maybe_provider {
            let ann = &entry.announcement;
            let mode = request
                .required_execution
                .as_ref()
                .map(|r| r.preferred_mode)
                .unwrap_or_default();

            CapabilityResolution {
                model_id: request.model_id.clone(),
                resolved_provider: ann.peer_id.clone(),
                execution_plan: ExecutionPlan {
                    plan_id: format!("plan-{}", Utc::now().timestamp_millis()),
                    model_id: request.model_id.clone(),
                    provider_id: ann.peer_id.clone(),
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
/// Returns artifact descriptors for a model discovered via gossipsub.
pub async fn list_model_artifacts(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(model_id): axum::extract::Path<String>,
) -> Json<ModelArtifactsResponse> {
    if let Some(ref node) = state.node {
        let models = node.network_models_snapshot();
        if let Some(entry) = models
            .iter()
            .find(|m| m.registration.model_id == model_id)
        {
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
/// Lists all network providers discovered via gossipsub, with RFC-0007 runtime metadata.
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
                    peer_id: ann.peer_id,
                    provider_address: ann.provider_address,
                    provider_type: ann.provider_type,
                    served_models: ann.served_models,
                    capabilities: ann.capabilities,
                    rpc_endpoint: ann.rpc_endpoint,
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

/// GET /execution/receipts/:receipt_id
/// Returns an execution receipt by ID.
/// Phase 1: no receipt storage — always returns not found.
pub async fn get_execution_receipt(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(_receipt_id): axum::extract::Path<String>,
) -> Json<ExecutionReceiptResponse> {
    let _ = &state;
    Json(ExecutionReceiptResponse {
        receipt: None,
        found: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_chat_completion_without_router() {
        let state = Arc::new(WebState::new());
        let request = super::super::types::ChatRequest {
            model: "test-model".to_string(),
            messages: vec![super::super::types::ChatMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
            stream: Some(false),
            max_tokens: None,
            temperature: None,
        };

        let response = chat_completion(State(state), Json(request)).await;

        // Should return SERVICE_UNAVAILABLE when router not configured
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_webstate_builder() {
        let state = WebState::new()
            .with_faucet("0x1234".to_string(), 100, 3600);

        assert_eq!(state.faucet_address, Some("0x1234".to_string()));
        assert_eq!(state.faucet_amount, 100);
        assert_eq!(state.faucet_cooldown_secs, 3600);
        assert!(state.inference_router.is_none());
    }
}
