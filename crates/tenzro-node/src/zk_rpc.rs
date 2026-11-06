//! Node entry points for zero-knowledge proofs.
//!
//! One implementation behind every surface: the JSON-RPC methods
//! (`tenzro_verifyZkProof`, `tenzro_createZkProof`, `tenzro_createTeeZkProof`,
//! `tenzro_verifyTeeZkProof`, `tenzro_listCircuits`, `tenzro_listZkCircuits`),
//! the MCP `verify_zk_proof` tool (which dispatches through the RPC) and the
//! web `POST /verify/zk-proof` route.
//!
//! A statement is submitted for attestation to the `ZK_VERIFY` registry
//! only when proofs of it verify in [`tenzro_zk::DIVERSE_THRESHOLD`] distinct
//! proof systems from at least [`tenzro_zk::diverse::MIN_IMPLEMENTATIONS`]
//! independent implementations. A single verifying leg is reported as valid
//! but is not submitted for attestation.

use std::sync::{Arc, OnceLock};

use serde_json::{Value, json};
use tenzro_zk::plonky3::config::{goldilocks, koala_bear};
use tenzro_zk::plonky3::soundness::{
    SoundnessReport, SystemParameters, preimage_air_shape, proven_security,
};
use tenzro_zk::{
    Circuit, DIVERSE_THRESHOLD, DiverseError, Proof, ProofSystem, TeeZkProof, statement_commitment,
    verify_k_of_n,
};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

fn invalid_params(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn server_error(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: message.into(),
        data: None,
    }
}

/// Accept `{...}` or `[{...}]`.
fn object_params(params: Option<Value>) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| invalid_params("Missing params"))?;
    Ok(match params.as_array() {
        Some(arr) => arr.first().cloned().unwrap_or(params),
        None => params,
    })
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())
}

fn word_param(params: &Value, key: &str) -> Result<[u8; 32], JsonRpcError> {
    let s = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params(format!("{key} is required (32-byte hex)")))?;
    let bytes = decode_hex(s).map_err(|e| invalid_params(format!("{key}: {e}")))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| invalid_params(format!("{key} must be 32 bytes, got {}", b.len())))
}

fn circuit_param(params: &Value) -> Result<Circuit, JsonRpcError> {
    let id = params
        .get("circuit_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("circuit_id is required (\"identity\" or \"settlement\")"))?;
    Circuit::parse(id).ok_or_else(|| {
        invalid_params(format!(
            "unknown circuit_id {id} (expected \"identity\" or \"settlement\")"
        ))
    })
}

/// Verify one statement from any number of proof legs, and submit it to the
/// attestation quorum when the legs span enough distinct proof systems.
///
/// `node` is `None` on a web server running without a node; verification
/// still runs, attestation does not.
pub(crate) async fn verify_statement(
    node: Option<&Arc<TenzroNode>>,
    circuit_id: String,
    public_inputs: Vec<Vec<u8>>,
    legs: Vec<(ProofSystem, Vec<u8>)>,
) -> Value {
    let envelopes: Vec<Proof> = legs
        .into_iter()
        .map(|(system, bytes)| {
            Proof::new_in(system, bytes, public_inputs.clone(), circuit_id.clone())
        })
        .collect();
    let statement = statement_commitment(&circuit_id, &public_inputs);

    let for_verify = envelopes.clone();
    let outcome =
        tokio::task::spawn_blocking(move || verify_k_of_n(&for_verify, DIVERSE_THRESHOLD))
            .await
            .map_err(|e| format!("verifier task failed: {e}"));

    let (valid, diverse, systems, error) = match outcome {
        Ok(Ok(verdict)) => (
            true,
            true,
            verdict
                .systems
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            None,
        ),
        Ok(Err(
            DiverseError::TooFewSystems { .. } | DiverseError::TooFewImplementations { .. },
        )) => {
            let mut systems: Vec<&str> = envelopes.iter().map(|p| p.system.as_str()).collect();
            systems.sort_unstable();
            systems.dedup();
            (true, false, systems, None)
        }
        Ok(Err(e)) => (false, false, Vec::new(), Some(e.to_string())),
        Err(e) => (false, false, Vec::new(), Some(e)),
    };

    // Attestation: every leg of an accepted statement is submitted as an
    // `AttestZkProof` transaction, which every validator re-verifies while
    // executing the block.
    let mut attested = Vec::new();
    if diverse && let Some(node) = node {
        for envelope in &envelopes {
            attested.push(json!({
                "system": envelope.system.as_str(),
                "commitment_hex": format!(
                    "0x{}",
                    hex::encode(tenzro_vm::precompiles::compute_zk_commitment(envelope))
                ),
                "attest_tx": match node.submit_zk_attestation(envelope).await {
                    Ok(hash) => json!(hash),
                    Err(e) => json!({ "error": e.to_string() }),
                },
            }));
        }
    }

    json!({
        "valid": valid,
        "circuit_id": circuit_id,
        "statement_commitment": format!("0x{}", hex::encode(statement)),
        "legs": envelopes.len(),
        "verified_systems": systems,
        "diverse_threshold": DIVERSE_THRESHOLD,
        "meets_diverse_threshold": diverse,
        "attestations": attested,
        "error": error,
        "note": "A statement is attested only when proofs of it verify in every configured \
                 proof system. Each leg is then submitted as an AttestZkProof transaction, \
                 which every validator re-verifies while executing the block; ZK_VERIFY \
                 reads the result from state.",
    })
}

/// `tenzro_verifyZkProof`.
///
/// Params: `circuit_id`, `public_inputs` (`[digest, binding]`, 32-byte hex
/// each), `proofs` (`[{system, proof}]`, proof as hex).
pub(crate) async fn handle_verify_zk_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params)?;
    let circuit_id = params
        .get("circuit_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_params("circuit_id is required (\"identity\" or \"settlement\")"))?
        .to_string();
    let public_inputs = params
        .get("public_inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid_params("public_inputs is required ([digest, binding] as hex)"))?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .ok_or_else(|| invalid_params(format!("public_inputs[{i}] must be a hex string")))
                .and_then(|s| {
                    decode_hex(s).map_err(|e| invalid_params(format!("public_inputs[{i}]: {e}")))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let legs = params
        .get("proofs")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid_params("proofs is required ([{system, proof}])"))?
        .iter()
        .enumerate()
        .map(|(i, leg)| {
            let system = leg
                .get("system")
                .and_then(|v| v.as_str())
                .and_then(ProofSystem::parse)
                .ok_or_else(|| {
                    invalid_params(format!(
                        "proofs[{i}].system must be one of {:?}",
                        ProofSystem::ALL.map(|s| s.as_str())
                    ))
                })?;
            let proof = leg
                .get("proof")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid_params(format!("proofs[{i}].proof is required")))
                .and_then(|s| {
                    decode_hex(s).map_err(|e| invalid_params(format!("proofs[{i}].proof: {e}")))
                })?;
            Ok((system, proof))
        })
        .collect::<Result<Vec<_>, JsonRpcError>>()?;

    Ok(verify_statement(Some(node), circuit_id, public_inputs, legs).await)
}

/// `tenzro_createZkProof` — prove a settlement statement in every proof
/// system.
///
/// Params: `circuit_id` (`"settlement"`), `witness` (32-byte hex service
/// result), `binding` (32-byte hex request binding).
///
/// Identity proofs are refused: the witness is the holder's secret and is
/// proven where it lives (`tenzro zk prove`), never sent to a node.
pub(crate) async fn handle_create_zk_proof(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params)?;
    let circuit = node_provable_circuit(&params)?;
    let witness = word_param(&params, "witness")?;
    let binding = word_param(&params, "binding")?;

    let proofs = tokio::task::spawn_blocking(move || {
        ProofSystem::ALL
            .into_iter()
            .map(|system| tenzro_zk::prove(system, circuit, &witness, &binding))
            .collect::<tenzro_zk::Result<Vec<Proof>>>()
    })
    .await
    .map_err(|e| server_error(format!("prover task failed: {e}")))?
    .map_err(|e| server_error(format!("proving failed: {e}")))?;

    let public_inputs = proofs[0].public_inputs.clone();
    Ok(json!({
        "circuit_id": circuit.id(),
        "public_inputs": public_inputs.iter().map(|p| format!("0x{}", hex::encode(p))).collect::<Vec<_>>(),
        "statement_commitment": format!("0x{}", hex::encode(statement_commitment(circuit.id(), &public_inputs))),
        "proofs": proofs.iter().map(|p| json!({
            "system": p.system.as_str(),
            "proof": format!("0x{}", hex::encode(&p.proof_bytes)),
            "proof_size_bytes": p.proof_bytes.len(),
        })).collect::<Vec<_>>(),
    }))
}

fn node_provable_circuit(params: &Value) -> Result<Circuit, JsonRpcError> {
    match circuit_param(params)? {
        Circuit::Identity => Err(invalid_params(
            "identity proofs are produced by the key holder (tenzro zk prove); a node never \
             receives an identity secret",
        )),
        c => Ok(c),
    }
}

/// `tenzro_createTeeZkProof` — prove a settlement statement inside this
/// node's TEE and bind the enclave's attestation to that exact proof.
///
/// Params: `circuit_id` (`"settlement"`), `vendor`, `witness`, `binding`.
pub(crate) async fn handle_create_tee_zk_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params)?;
    let circuit = node_provable_circuit(&params)?;
    let vendor_str = params
        .get("vendor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            invalid_params("vendor is required (intel-tdx | amd-sev-snp | aws-nitro | intel-sgx)")
        })?;
    let vendor = parse_tee_vendor(vendor_str)?;
    let witness = word_param(&params, "witness")?;
    let binding = word_param(&params, "binding")?;

    // Fail closed without an enclave, and on a vendor this node is not
    // running: a report for hardware that is not present attests to nothing.
    let provider = node.tee_provider().ok_or_else(|| JsonRpcError {
        code: -32001,
        message: "no TEE hardware on this node; a TEE-bound ZK proof cannot be produced \
                  without an enclave to attest it"
            .to_string(),
        data: None,
    })?;
    if provider.vendor() != vendor {
        return Err(invalid_params(format!(
            "this node's TEE is {:?}, not {vendor:?}",
            provider.vendor()
        )));
    }

    let proof = tokio::task::spawn_blocking(move || {
        tenzro_zk::prove(ProofSystem::KoalaBearSha256Fri, circuit, &witness, &binding)
    })
    .await
    .map_err(|e| server_error(format!("prover task failed: {e}")))?
    .map_err(|e| server_error(format!("proving failed: {e}")))?;

    // The enclave attests to the proof's binding digest, which commits to the
    // circuit, the proof system, every public input and the proof bytes.
    let binding_digest = TeeZkProof::binding_digest(&proof);
    let attestation = provider
        .generate_attestation(&binding_digest)
        .await
        .map_err(|e| server_error(format!("the enclave declined to attest: {e}")))?;
    let bundle = tenzro_zk::bind_tee_attestation(proof, attestation)
        .map_err(|e| server_error(format!("attestation does not bind the proof: {e}")))?;

    Ok(json!({
        "tee_zk_proof": bundle,
        "binding_digest": format!("0x{}", hex::encode(binding_digest)),
        "circuit_id": circuit.id(),
        "vendor": vendor_str,
    }))
}

fn parse_tee_vendor(raw: &str) -> Result<tenzro_types::tee::TeeVendor, JsonRpcError> {
    use tenzro_types::tee::TeeVendor;
    match raw.to_lowercase().as_str() {
        "intel-tdx" | "tdx" | "intel_tdx" => Ok(TeeVendor::IntelTdx),
        "intel-sgx" | "sgx" | "intel_sgx" => Ok(TeeVendor::IntelSGX),
        "amd-sev-snp" | "sev-snp" | "amd_sev_snp" | "sev_snp" => Ok(TeeVendor::AmdSevSnp),
        "aws-nitro" | "nitro" | "aws_nitro" => Ok(TeeVendor::AwsNitro),
        other => Err(invalid_params(format!(
            "Unknown TEE vendor: {other} (expected intel-tdx | intel-sgx | amd-sev-snp | aws-nitro)"
        ))),
    }
}

/// `tenzro_verifyTeeZkProof` — verify a TEE-bound proof bundle.
///
/// Params: `tee_zk_proof` (the bundle returned by `tenzro_createTeeZkProof`).
/// `admitted` is true only when the STARK verifies, the attestation's signed
/// report data equals the proof's binding digest, and the attestation passes
/// `tenzro_tee::verify_report` (vendor signature chained to a pinned root,
/// current collateral, and that binding digest as its signed report data).
pub(crate) async fn handle_verify_tee_zk_proof(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = object_params(params)?;
    let bundle: TeeZkProof = serde_json::from_value(
        params
            .get("tee_zk_proof")
            .cloned()
            .ok_or_else(|| invalid_params("tee_zk_proof is required"))?,
    )
    .map_err(|e| invalid_params(format!("Invalid tee_zk_proof JSON: {e}")))?;

    let for_verify = bundle.clone();
    let proof_and_binding =
        tokio::task::spawn_blocking(move || tenzro_zk::verify_tee_zk_proof(&for_verify))
            .await
            .map_err(|e| server_error(format!("verifier task failed: {e}")))?;

    // The report must carry the proof's binding digest in its hardware-signed
    // report data, packed for its vendor as every attester packs it.
    let digest = TeeZkProof::binding_digest(&bundle.zk_proof);
    let expected =
        tenzro_types::tee::pack_user_data_for_vendor(bundle.tee_attestation.vendor, &digest);
    let attestation = tenzro_tee::verify_report(
        &bundle.tee_attestation,
        &tenzro_tee::VerifyPolicy::now(expected),
    );

    let proof_error = proof_and_binding.as_ref().err().map(|e| e.to_string());
    let attestation_error = attestation.as_ref().err().map(|e| e.to_string());
    Ok(json!({
        "admitted": proof_and_binding.is_ok() && attestation.is_ok(),
        "circuit_id": bundle.zk_proof.circuit_id,
        "system": bundle.zk_proof.system.as_str(),
        "proof_and_binding_valid": proof_and_binding.is_ok(),
        "proof_and_binding_error": proof_error,
        "attestation_valid": attestation.is_ok(),
        "attestation_error": attestation_error,
        "vendor": format!("{:?}", bundle.tee_attestation.vendor),
        "binding_digest": format!("0x{}", hex::encode(TeeZkProof::binding_digest(&bundle.zk_proof))),
    }))
}

/// `tenzro_attestFinalityProof` — bind a Groth16-wrapped finality proof (the
/// compact form over BN254, which rests on a classical assumption and is not
/// quantum-safe; the STARK is the default form everywhere else) made on this
/// machine to an attestation of this node's TEE.
///
/// Params: `image_id`, `journal`, `seal` (hex, as `tenzro-finality-prover
/// wrap` writes them). The seal is verified first, so the enclave never
/// vouches for a proof that does not verify. The attestation's report data
/// commits to the program, the journal, the seal and the prover
/// ([`tenzro_zk::finality_proof::GROTH16_PROVER_IMAGE`]).
pub(crate) async fn handle_attest_finality_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_zk::finality_proof::{TeeFinalityProof, groth16_prover_digest};
    let params = object_params(params)?;
    let image_id = word_param(&params, "image_id")?;
    let bytes = |key: &str| -> Result<Vec<u8>, JsonRpcError> {
        params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params(format!("{key} is required (hex)")))
            .and_then(|s| decode_hex(s).map_err(|e| invalid_params(format!("{key}: {e}"))))
    };
    let journal = bytes("journal")?;
    let seal = bytes("seal")?;

    let provider = node.tee_provider().ok_or_else(|| JsonRpcError {
        code: -32001,
        message: "no TEE hardware on this node; a finality proof cannot be attested without an \
                  enclave"
            .to_string(),
        data: None,
    })?;
    {
        let (journal, seal) = (journal.clone(), seal.clone());
        tokio::task::spawn_blocking(move || {
            tenzro_zk::finality_proof::verify_groth16(&image_id, &journal, &seal)
        })
        .await
        .map_err(|e| server_error(format!("verifier task failed: {e}")))?
        .map_err(|e| invalid_params(format!("the finality proof does not verify: {e}")))?;
    }
    let prover_digest = groth16_prover_digest();
    let digest = TeeFinalityProof::binding_digest(&image_id, &journal, &seal, &prover_digest);
    let tee_attestation = provider
        .generate_attestation(&digest)
        .await
        .map_err(|e| server_error(format!("the enclave declined to attest: {e}")))?;
    let bundle = TeeFinalityProof {
        image_id,
        journal,
        seal,
        prover_digest,
        tee_attestation,
    };
    tenzro_zk::verify_tee_finality_proof(&bundle)
        .map_err(|e| server_error(format!("attestation does not bind the proof: {e}")))?;
    let measurements = crate::attestation_rpc::measurements_json(
        &tenzro_tee::measurements::evidence_measurements(&bundle.tee_attestation),
    );
    Ok(json!({
        "vendor": format!("{:?}", bundle.tee_attestation.vendor),
        "binding_digest": format!("0x{}", hex::encode(digest)),
        "measurements": measurements,
        "tee_finality_proof": bundle,
    }))
}

/// `tenzro_verifyTeeFinalityProof` — verify a finality proof bundle from
/// `tenzro_attestFinalityProof`.
///
/// `admitted` is true only when the seal verifies, the prover is the published
/// one, the attestation's signed report data carries the binding digest, and
/// the attestation passes `tenzro_tee::verify_report`. The verified
/// measurement registers are returned for comparison with the published
/// measurements of the image the prover ran in.
pub(crate) async fn handle_verify_tee_finality_proof(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_zk::finality_proof::TeeFinalityProof;
    let params = object_params(params)?;
    let bundle: TeeFinalityProof = serde_json::from_value(
        params
            .get("tee_finality_proof")
            .cloned()
            .ok_or_else(|| invalid_params("tee_finality_proof is required"))?,
    )
    .map_err(|e| invalid_params(format!("Invalid tee_finality_proof JSON: {e}")))?;

    let for_verify = bundle.clone();
    let proof_and_binding =
        tokio::task::spawn_blocking(move || tenzro_zk::verify_tee_finality_proof(&for_verify))
            .await
            .map_err(|e| server_error(format!("verifier task failed: {e}")))?;
    let expected = tenzro_types::tee::pack_user_data_for_vendor(
        bundle.tee_attestation.vendor,
        &bundle.digest(),
    );
    let attestation = tenzro_tee::verify_report(
        &bundle.tee_attestation,
        &tenzro_tee::VerifyPolicy::now(expected),
    );

    let measurements = match &attestation {
        Ok(v) => crate::attestation_rpc::measurements_json(&v.measurements),
        Err(_) => Value::Array(Vec::new()),
    };
    Ok(json!({
        "admitted": proof_and_binding.is_ok() && attestation.is_ok(),
        "proof_and_binding_valid": proof_and_binding.is_ok(),
        "proof_and_binding_error": proof_and_binding.as_ref().err().map(|e| e.to_string()),
        "attestation_valid": attestation.is_ok(),
        "attestation_error": attestation.as_ref().err().map(|e| e.to_string()),
        "tcb_status": attestation.as_ref().ok().map(|v| v.tcb_status.clone()),
        "vendor": format!("{:?}", bundle.tee_attestation.vendor),
        "image_id": format!("0x{}", hex::encode(bundle.image_id)),
        "prover_digest": format!("0x{}", hex::encode(bundle.prover_digest)),
        "binding_digest": format!("0x{}", hex::encode(bundle.digest())),
        "measurements": measurements,
    }))
}

/// Security of the Halo2 system: its soundness rests on discrete logarithms
/// in the Pallas group (order about 2^254), which generic attacks solve in
/// about 2^126.9 group operations.
const HALO2_SECURITY_BITS: u32 = 126;

fn system_entry(system: ProofSystem, params: &SystemParameters, report: &SoundnessReport) -> Value {
    json!({
        "system": system.as_str(),
        "implementation": "plonky3",
        "base_field_bits": params.base_field_bits,
        "extension_degree": params.extension_degree,
        "fri_log_blowup": params.log_blowup,
        "fri_queries": params.num_queries,
        "query_pow_bits": params.query_pow_bits,
        "proven_security_bits": (report.proven_bits * 10.0).floor() / 10.0,
        "conjectured_security_bits": report.conjectured_bits,
    })
}

/// The circuit catalogue, with the proven soundness of each proof system.
fn circuit_catalogue() -> &'static Vec<Value> {
    static CATALOGUE: OnceLock<Vec<Value>> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        let shape = preimage_air_shape();
        let systems = vec![
            system_entry(
                ProofSystem::KoalaBearSha256Fri,
                &koala_bear::PARAMETERS,
                &proven_security(&koala_bear::PARAMETERS, &shape),
            ),
            system_entry(
                ProofSystem::GoldilocksBlake3Fri,
                &goldilocks::PARAMETERS,
                &proven_security(&goldilocks::PARAMETERS, &shape),
            ),
            json!({
                "system": ProofSystem::Halo2IpaPasta.as_str(),
                "implementation": "halo2",
                "field": "Pallas scalar field (255 bits)",
                "commitment": "inner-product argument over Pallas, no trusted setup",
                "transcript_hash": "BLAKE2b",
                "circuit_rows_log2": tenzro_zk::halo2::K,
                "computational_security_bits": HALO2_SECURITY_BITS,
            }),
        ];
        Circuit::ALL
            .into_iter()
            .map(|c| {
                json!({
                    "type": c.id(),
                    "name": "PreimageAir",
                    "statement": match c {
                        Circuit::Identity => "knowledge of the 32-byte secret whose SHA3-256 under the identity domain is the public digest",
                        Circuit::Settlement => "knowledge of the 32-byte service result whose SHA3-256 under the settlement domain is the public digest",
                    },
                    "public_inputs": ["digest (32 bytes)", "binding (32 bytes)"],
                    "in_circuit_hash": "keccak-f[1600] (SHA3-256)",
                    "node_provable": c != Circuit::Identity,
                    "proof_systems": systems,
                    "diverse_threshold": DIVERSE_THRESHOLD,
                })
            })
            .collect()
    })
}

/// `tenzro_listCircuits`.
pub(crate) async fn handle_list_circuits(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let circuits = circuit_catalogue();
    Ok(json!({
        "circuits": circuits,
        "total": circuits.len(),
    }))
}

/// `tenzro_listZkCircuits` — the same catalogue as a top-level array.
pub(crate) async fn handle_list_zk_circuits(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    Ok(Value::Array(circuit_catalogue().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITNESS: [u8; 32] = [0x21; 32];
    const BINDING: [u8; 32] = [0x43; 32];

    fn legs() -> Vec<Proof> {
        static LEGS: OnceLock<Vec<Proof>> = OnceLock::new();
        LEGS.get_or_init(|| {
            ProofSystem::ALL
                .into_iter()
                .map(|s| tenzro_zk::prove(s, Circuit::Settlement, &WITNESS, &BINDING).unwrap())
                .collect()
        })
        .clone()
    }

    #[tokio::test]
    async fn every_system_meets_the_threshold() {
        let legs = legs();
        let v = verify_statement(
            None,
            "settlement".to_string(),
            legs[0].public_inputs.clone(),
            legs.iter()
                .map(|p| (p.system, p.proof_bytes.clone()))
                .collect(),
        )
        .await;
        assert_eq!(v["valid"], true);
        assert_eq!(v["meets_diverse_threshold"], true);
    }

    #[tokio::test]
    async fn one_system_is_valid_but_not_submitted() {
        let legs = legs();
        let v = verify_statement(
            None,
            "settlement".to_string(),
            legs[0].public_inputs.clone(),
            vec![(legs[0].system, legs[0].proof_bytes.clone())],
        )
        .await;
        assert_eq!(v["valid"], true);
        assert_eq!(v["meets_diverse_threshold"], false);
        assert_eq!(v["attestations"].as_array().unwrap().len(), 0);
    }

    /// Someone who knows only the digest pairs a real proof of a different
    /// witness with it.
    #[tokio::test]
    async fn proofs_against_someone_elses_digest_are_invalid() {
        let legs = legs();
        let victim = vec![
            Circuit::Settlement.digest(&[0x99; 32]).to_vec(),
            BINDING.to_vec(),
        ];
        let v = verify_statement(
            None,
            "settlement".to_string(),
            victim,
            legs.iter()
                .map(|p| (p.system, p.proof_bytes.clone()))
                .collect(),
        )
        .await;
        assert_eq!(v["valid"], false);
        assert_eq!(v["meets_diverse_threshold"], false);
    }

    #[test]
    fn identity_is_not_node_provable() {
        let err = node_provable_circuit(&json!({"circuit_id": "identity"})).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(
            node_provable_circuit(&json!({"circuit_id": "settlement"})).unwrap(),
            Circuit::Settlement
        );
        assert!(node_provable_circuit(&json!({"circuit_id": "inference"})).is_err());
    }

    #[test]
    fn catalogue_reports_the_security_of_every_system() {
        for c in circuit_catalogue() {
            let systems = c["proof_systems"].as_array().unwrap();
            assert_eq!(systems.len(), ProofSystem::ALL.len());
            for s in systems {
                match s["implementation"].as_str().unwrap() {
                    "plonky3" => {
                        assert!(s["proven_security_bits"].as_f64().unwrap() >= 128.0, "{s}")
                    }
                    "halo2" => assert!(
                        s["computational_security_bits"].as_u64().unwrap() >= 126,
                        "{s}"
                    ),
                    other => panic!("unexpected implementation {other}"),
                }
            }
        }
    }
}
