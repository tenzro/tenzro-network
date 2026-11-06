//! Binding a proof to the TEE attestation that produced it.
//!
//! A [`TeeZkProof`] pairs a proof with an attestation report whose signed
//! report data is [`TeeZkProof::binding_digest`] of that proof. The flow:
//!
//! 1. Inside the enclave, prove the statement ([`crate::prove`]).
//! 2. Ask the enclave for an attestation over `binding_digest(&proof)`.
//! 3. [`bind_tee_attestation`] checks the report really carries that digest
//!    and bundles the two.
//!
//! [`verify_tee_zk_proof`] re-checks both halves: the STARK verifies, and the
//! report data extracted from the signed evidence equals the proof's binding
//! digest. The vendor signature over the evidence (quote chain, TCB, freshness)
//! is checked by `tenzro-tee`'s strict verifier at the call site; this module
//! has no access to vendor roots. Because the vendor signature covers the
//! report data, and the report data commits to the circuit, the proof system,
//! every public input and the proof bytes, an attestation cannot be lifted onto
//! a different proof or statement.
//!
//! There is no second, enclave-held signing key. A key held by the enclave
//! would either be derived from the TEE (which this codebase does not treat
//! as custody) or supplied from outside (which makes it self-certifying); the
//! attestation signature already is the enclave's signature over the proof.

use tenzro_types::tee::{AttestationReport, TeeVendor};

use crate::error::{Result, ZkError};
use crate::plonky3::verify_envelope::verify_proof_envelope;
use crate::proof::{Proof, TeeZkProof};

/// REPORT_DATA / REPORTDATA is 64 bytes on every Intel/AMD report format.
const REPORT_DATA_LEN: usize = 64;

/// Intel SGX DCAP ECDSA quote v3: 48-byte quote header followed by the
/// 384-byte ISV enclave report body; REPORT_DATA sits at body offset 320.
const SGX_QUOTE_REPORT_DATA_OFFSET: usize = 48 + 320; // = 368
const SGX_QUOTE_MIN_LEN: usize = SGX_QUOTE_REPORT_DATA_OFFSET + REPORT_DATA_LEN; // = 432

/// Intel TDX quote v4: 48-byte quote header followed by the 584-byte
/// TD report body (TDREPORT_STRUCT); REPORTDATA sits at body offset 520.
const TDX_QUOTE_REPORT_DATA_OFFSET: usize = 48 + 520; // = 568
const TDX_QUOTE_MIN_LEN: usize = TDX_QUOTE_REPORT_DATA_OFFSET + REPORT_DATA_LEN; // = 632

/// AMD SEV-SNP ATTESTATION_REPORT: report_data at struct offset 0x50.
const SNP_REPORT_DATA_OFFSET: usize = 0x50; // = 80
const SNP_REPORT_MIN_LEN: usize = SNP_REPORT_DATA_OFFSET + REPORT_DATA_LEN; // = 144

/// Bundle `proof` with `attestation`, refusing a report that does not carry
/// the proof's binding digest.
pub fn bind_tee_attestation(proof: Proof, attestation: AttestationReport) -> Result<TeeZkProof> {
    check_report_binds(&proof, &attestation)?;
    Ok(TeeZkProof {
        zk_proof: proof,
        tee_attestation: attestation,
        created_at: tenzro_types::primitives::Timestamp::now(),
    })
}

/// Verify the proof and its binding to the attestation.
///
/// Returns `Ok(())` when the STARK verifies and the attestation's signed
/// report data equals the proof's binding digest. The caller must still verify
/// the attestation evidence itself with the strict TEE verifier.
pub fn verify_tee_zk_proof(bundle: &TeeZkProof) -> Result<()> {
    verify_proof_envelope(&bundle.zk_proof).map_err(|e| ZkError::ProofRejected(e.to_string()))?;
    check_report_binds(&bundle.zk_proof, &bundle.tee_attestation)
}

fn check_report_binds(proof: &Proof, report: &AttestationReport) -> Result<()> {
    report_carries_digest(&TeeZkProof::binding_digest(proof), report)
}

/// Check that `report`'s signed report data carries `digest`, packed for its
/// vendor the way every attester packs it
/// ([`tenzro_types::tee::pack_user_data_for_vendor`]).
pub fn report_carries_digest(digest: &[u8; 32], report: &AttestationReport) -> Result<()> {
    let carried = extract_report_data(report)?;
    let expected = tenzro_types::tee::pack_user_data_for_vendor(report.vendor, digest);
    if carried == expected {
        Ok(())
    } else {
        Err(ZkError::TeeAttestationError(
            "attestation report data does not carry this proof's binding digest".to_string(),
        ))
    }
}

/// Extract `user_data` from an AWS Nitro attestation document.
///
/// The document is a COSE_Sign1 structure (RFC 8152 §4.2): a CBOR array of
/// four elements whose third entry (index 2) is the payload — a CBOR map
/// that carries the `user_data` byte string the enclave requested. A bare
/// payload map is also accepted.
fn nitro_user_data(evidence: &[u8]) -> Result<Vec<u8>> {
    let value: ciborium::value::Value = ciborium::de::from_reader(evidence).map_err(|e| {
        ZkError::TeeAttestationError(format!("Nitro document is not valid CBOR: {e}"))
    })?;

    let payload_value = match value {
        ciborium::value::Value::Array(items) => {
            if items.len() != 4 {
                return Err(ZkError::TeeAttestationError(format!(
                    "Nitro COSE_Sign1 must have 4 elements, got {}",
                    items.len()
                )));
            }
            match &items[2] {
                ciborium::value::Value::Bytes(payload) => {
                    ciborium::de::from_reader(payload.as_slice()).map_err(|e| {
                        ZkError::TeeAttestationError(format!(
                            "Nitro COSE_Sign1 payload is not valid CBOR: {e}"
                        ))
                    })?
                }
                _ => {
                    return Err(ZkError::TeeAttestationError(
                        "Nitro COSE_Sign1 payload is not a byte string".to_string(),
                    ));
                }
            }
        }
        map @ ciborium::value::Value::Map(_) => map,
        _ => {
            return Err(ZkError::TeeAttestationError(
                "Nitro document is neither COSE_Sign1 array nor attestation map".to_string(),
            ));
        }
    };

    let ciborium::value::Value::Map(entries) = payload_value else {
        return Err(ZkError::TeeAttestationError(
            "Nitro attestation payload is not a CBOR map".to_string(),
        ));
    };

    for (key, val) in &entries {
        if matches!(key, ciborium::value::Value::Text(k) if k == "user_data") {
            return match val {
                ciborium::value::Value::Bytes(data) if !data.is_empty() => Ok(data.clone()),
                _ => Err(ZkError::TeeAttestationError(
                    "Nitro attestation user_data is empty or not a byte string".to_string(),
                )),
            };
        }
    }

    Err(ZkError::TeeAttestationError(
        "Nitro attestation document carries no user_data field".to_string(),
    ))
}

/// Slice the 64-byte REPORT_DATA out of raw quote/report evidence.
fn report_data_at(evidence: &[u8], offset: usize, min_len: usize, format: &str) -> Result<Vec<u8>> {
    if evidence.len() < min_len {
        return Err(ZkError::TeeAttestationError(format!(
            "{format} evidence too short: {} bytes, need at least {min_len}",
            evidence.len()
        )));
    }
    Ok(evidence[offset..offset + REPORT_DATA_LEN].to_vec())
}

/// Extract the caller-supplied report data from the signed evidence.
///
/// Read from the evidence bytes the vendor signed, never from the report's
/// unsigned `user_data` copy:
///
/// - **Intel SGX** (DCAP ECDSA quote v3): REPORT_DATA at quote offset 368.
/// - **Intel TDX** (quote v4): REPORTDATA at quote offset 568.
/// - **AMD SEV-SNP**: report_data at ATTESTATION_REPORT offset 0x50.
/// - **AWS Nitro**: the `user_data` entry of the attestation document.
///
/// Vendors with no standardized report-data field fail closed.
fn extract_report_data(report: &AttestationReport) -> Result<Vec<u8>> {
    let evidence: &[u8] = if !report.attestation_data.is_empty() {
        &report.attestation_data
    } else {
        &report.quote
    };
    if evidence.is_empty() {
        return Err(ZkError::TeeAttestationError(
            "attestation report carries no quote evidence".to_string(),
        ));
    }

    match report.vendor {
        TeeVendor::IntelSGX => report_data_at(
            evidence,
            SGX_QUOTE_REPORT_DATA_OFFSET,
            SGX_QUOTE_MIN_LEN,
            "SGX DCAP quote",
        ),
        TeeVendor::IntelTdx => report_data_at(
            evidence,
            TDX_QUOTE_REPORT_DATA_OFFSET,
            TDX_QUOTE_MIN_LEN,
            "TDX quote",
        ),
        TeeVendor::AMDSEV | TeeVendor::AmdSevSnp => report_data_at(
            evidence,
            SNP_REPORT_DATA_OFFSET,
            SNP_REPORT_MIN_LEN,
            "SEV-SNP report",
        ),
        TeeVendor::AWSNitro | TeeVendor::AwsNitro => nitro_user_data(evidence),
        other => Err(ZkError::TeeAttestationError(format!(
            "{other:?} has no standardized report-data field"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::Circuit;
    use crate::plonky3::prove;
    use crate::proof::ProofSystem;

    fn proof() -> Proof {
        prove(
            ProofSystem::KoalaBearSha256Fri,
            Circuit::Settlement,
            &[0x31; 32],
            &[0x32; 32],
        )
        .unwrap()
    }

    /// Evidence of `total_len` bytes with `user_data` zero-padded into the
    /// 64-byte report-data field at `offset`.
    fn evidence(total_len: usize, offset: usize, user_data: &[u8]) -> Vec<u8> {
        let mut e = vec![0xAAu8; total_len];
        e[offset..offset + 64].fill(0);
        e[offset..offset + user_data.len()].copy_from_slice(user_data);
        e
    }

    fn nitro_document(user_data: Option<Vec<u8>>) -> Vec<u8> {
        use ciborium::value::Value;
        let mut entries = vec![(
            Value::Text("module_id".to_string()),
            Value::Text("i-0abc".to_string()),
        )];
        if let Some(d) = user_data {
            entries.push((Value::Text("user_data".to_string()), Value::Bytes(d)));
        }
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut payload).unwrap();
        let doc = Value::Array(vec![
            Value::Bytes(vec![0xA0]),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(vec![0u8; 96]),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&doc, &mut out).unwrap();
        out
    }

    /// A report whose report data is `digest` packed for `vendor`, as an
    /// attester's provider produces it.
    fn report_for(vendor: TeeVendor, digest: &[u8; 32]) -> AttestationReport {
        let packed = tenzro_types::tee::pack_user_data_for_vendor(vendor, digest);
        let digest = packed.as_slice();
        let data = match vendor {
            TeeVendor::IntelSGX => {
                evidence(SGX_QUOTE_MIN_LEN, SGX_QUOTE_REPORT_DATA_OFFSET, digest)
            }
            TeeVendor::IntelTdx => {
                evidence(TDX_QUOTE_MIN_LEN, TDX_QUOTE_REPORT_DATA_OFFSET, digest)
            }
            TeeVendor::AmdSevSnp => evidence(SNP_REPORT_MIN_LEN, SNP_REPORT_DATA_OFFSET, digest),
            TeeVendor::AwsNitro => nitro_document(Some(digest.to_vec())),
            other => panic!("no evidence layout for {other:?}"),
        };
        AttestationReport::new(vendor, data, vec![], vec![])
    }

    #[test]
    fn attestation_over_the_binding_digest_binds_for_every_vendor() {
        let p = proof();
        let digest = TeeZkProof::binding_digest(&p);
        for vendor in [
            TeeVendor::IntelSGX,
            TeeVendor::IntelTdx,
            TeeVendor::AmdSevSnp,
            TeeVendor::AwsNitro,
        ] {
            let bundle = bind_tee_attestation(p.clone(), report_for(vendor, &digest))
                .unwrap_or_else(|e| panic!("{vendor:?}: {e}"));
            verify_tee_zk_proof(&bundle).unwrap_or_else(|e| panic!("{vendor:?}: {e}"));
        }
    }

    /// An attestation produced for one proof is attached to another proof of
    /// the same circuit.
    #[test]
    fn attestation_for_one_proof_does_not_bind_another() {
        let p = proof();
        let report = report_for(TeeVendor::IntelTdx, &TeeZkProof::binding_digest(&p));
        let other = prove(
            ProofSystem::KoalaBearSha256Fri,
            Circuit::Settlement,
            &[0x31; 32],
            &[0x33; 32],
        )
        .unwrap();
        assert!(bind_tee_attestation(other.clone(), report.clone()).is_err());

        let forged = TeeZkProof {
            zk_proof: other,
            tee_attestation: report,
            created_at: tenzro_types::primitives::Timestamp::now(),
        };
        assert!(verify_tee_zk_proof(&forged).is_err());
    }

    /// An attestation whose report data carries only the circuit label, which
    /// is what a report bound to the circuit alone looks like.
    #[test]
    fn attestation_bound_to_the_circuit_alone_is_rejected() {
        use sha2::{Digest, Sha256};
        let p = proof();
        let circuit_only: [u8; 32] = Sha256::digest(b"tenzro/zk/tee-bound-proofsettlement").into();
        let report = report_for(TeeVendor::AmdSevSnp, &circuit_only);
        assert!(bind_tee_attestation(p, report).is_err());
    }

    /// The report's unsigned `user_data` copy is never trusted.
    #[test]
    fn unsigned_user_data_copy_is_ignored() {
        let p = proof();
        let mut report = report_for(TeeVendor::IntelSGX, &[0u8; 32]);
        report.user_data = TeeZkProof::binding_digest(&p).to_vec();
        assert!(bind_tee_attestation(p, report).is_err());
    }

    /// The bare digest zero-padded into the field is not what an attester's
    /// provider signs, so it does not bind.
    #[test]
    fn an_unpacked_digest_does_not_bind() {
        let p = proof();
        let digest = TeeZkProof::binding_digest(&p);
        let report = AttestationReport::new(
            TeeVendor::IntelTdx,
            evidence(TDX_QUOTE_MIN_LEN, TDX_QUOTE_REPORT_DATA_OFFSET, &digest),
            vec![],
            vec![],
        );
        assert!(bind_tee_attestation(p, report).is_err());
    }

    #[test]
    fn tampered_proof_inside_a_bound_bundle_fails() {
        let p = proof();
        let report = report_for(TeeVendor::IntelTdx, &TeeZkProof::binding_digest(&p));
        let mut bundle = bind_tee_attestation(p, report).unwrap();
        bundle.zk_proof.public_inputs[0][0] ^= 1;
        assert!(verify_tee_zk_proof(&bundle).is_err());
    }

    #[test]
    fn evidence_problems_fail_closed() {
        let p = proof();
        let short = AttestationReport::new(TeeVendor::IntelSGX, vec![0u8; 100], vec![], vec![]);
        assert!(bind_tee_attestation(p.clone(), short).is_err());
        let empty = AttestationReport::new(TeeVendor::IntelTdx, vec![], vec![], vec![]);
        assert!(bind_tee_attestation(p.clone(), empty).is_err());
        let generic = AttestationReport::new(TeeVendor::Generic, vec![0u8; 1024], vec![], vec![]);
        assert!(bind_tee_attestation(p.clone(), generic).is_err());
        let nitro =
            AttestationReport::new(TeeVendor::AwsNitro, nitro_document(None), vec![], vec![]);
        assert!(bind_tee_attestation(p, nitro).is_err());
    }
}
