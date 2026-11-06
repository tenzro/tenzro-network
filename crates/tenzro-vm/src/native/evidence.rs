//! Checking evidence against chain state (see [`tenzro_types::evidence`]),
//! and the finality program whose proofs the chain accepts.
//!
//! Nothing here writes: a check reads the epoch roots nodes committed, the
//! terms agents hold, recorded settlements, registered hardware keys and the
//! governed finality program, and says what each item proves.

use sha2::{Digest, Sha256};
use tenzro_types::evidence::{
    CheckedEvidence, Evidence, finality_proof_digest, sensor_reading_digest,
};

use super::funding::{read_json, refuse, write_json};
use super::*;

/// System storage key of the finality program's image id.
pub const FINALITY_PROGRAM_KEY: &str = "finality_program";

/// The image id of the finality program whose proofs the chain accepts, if
/// one is set.
pub fn read_finality_program(state: &dyn VmState) -> Option<[u8; 32]> {
    let hex: String = read_json(state, FINALITY_PROGRAM_KEY)?;
    hex::decode(hex).ok()?.try_into().ok()
}

/// Sets the finality program; governance and genesis write it.
pub(super) fn set_finality_program(
    state: &mut dyn VmState,
    image_id: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, FINALITY_PROGRAM_KEY, &hex::encode(image_id), changes)?;
    Ok(())
}

/// System storage key of the handover program's image id.
pub const HANDOVER_PROGRAM_KEY: &str = "handover_program";

/// The image id of the handover program whose proofs of the epoch handover
/// chain nodes accept, if one is set.
pub fn read_handover_program(state: &dyn VmState) -> Option<[u8; 32]> {
    let hex: String = read_json(state, HANDOVER_PROGRAM_KEY)?;
    hex::decode(hex).ok()?.try_into().ok()
}

/// Sets the handover program; governance and genesis write it.
pub(super) fn set_handover_program(
    state: &mut dyn VmState,
    image_id: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, HANDOVER_PROGRAM_KEY, &hex::encode(image_id), changes)?;
    Ok(())
}

fn digest_of<T: serde::Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(value).unwrap_or_default()).into()
}

/// Check each evidence item against chain state. An item that claims what
/// state does not hold is refused with the reason; a document is bound by
/// its digest and reported unverified.
pub fn check_evidence(state: &dyn VmState, items: &[Evidence]) -> Result<Vec<CheckedEvidence>> {
    Evidence::validate(items).map_err(refuse)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (kind, digest, verified) = match item {
            Evidence::Audit(proof) => {
                let root = proof
                    .verify()
                    .map_err(|e| refuse(format!("audit evidence does not verify: {e}")))?;
                let committer = hex::decode(proof.committer.trim_start_matches("0x"))
                    .map_err(|_| refuse("audit evidence names a committer that is not hex"))?;
                let committed = agent_audit::read_agent_audit(state, &committer, proof.epoch)
                    .ok_or_else(|| refuse("no audit root is committed for that node and epoch"))?;
                if committed.root != hex::encode(root) {
                    return Err(refuse("audit evidence does not reach the committed root"));
                }
                ("audit".to_string(), digest_of(proof), true)
            }
            Evidence::Terms { agent_did } => {
                let terms = agent_terms::read_agent_terms(state, agent_did)
                    .ok_or_else(|| refuse(format!("{agent_did} holds no terms on chain")))?;
                ("terms".to_string(), digest_of(&terms), true)
            }
            Evidence::Settlement { payment_id } => {
                if payment_settlement::read_payment_by_id(state, payment_id).is_none() {
                    return Err(refuse(format!(
                        "no settlement is recorded under {payment_id}"
                    )));
                }
                (
                    "settlement".to_string(),
                    Sha256::digest(payment_id.as_bytes()).into(),
                    true,
                )
            }
            Evidence::SensorData {
                device_did,
                payload_digest,
                measured_at_ms,
                signature,
            } => {
                let digest = sensor_reading_digest(device_did, payload_digest, *measured_at_ms);
                verify_device_signature(state, device_did, &digest, signature)?;
                ("sensor_data".to_string(), digest, true)
            }
            Evidence::FinalityProof {
                journal,
                stark,
                seal,
            } => {
                use tenzro_zk::finality_proof::ProofForm;
                let (form, proof, kind) = match (stark.is_empty(), seal.is_empty()) {
                    (false, true) => (ProofForm::Stark, stark, "finality_proof"),
                    (true, false) => (ProofForm::Groth16Bn254, seal, "finality_proof_groth16"),
                    _ => {
                        return Err(refuse(
                            "a finality proof carries exactly one of a stark and a seal",
                        ));
                    }
                };
                let image_id = read_finality_program(state)
                    .ok_or_else(|| refuse("no finality program is configured on chain"))?;
                tenzro_zk::finality_proof::verify(form, &image_id, journal, proof)
                    .map_err(|e| refuse(format!("the finality proof does not verify: {e}")))?;
                let stated = tenzro_finality::step::FinalityJournal::decode(journal)
                    .ok_or_else(|| refuse("the finality proof's journal does not decode"))?;
                (
                    kind.to_string(),
                    finality_proof_digest(&stated.checkpoint_digest, &stated.committee_root),
                    true,
                )
            }
            Evidence::Document { kind, digest } => (
                serde_json::to_value(kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                *digest,
                false,
            ),
        };
        out.push(CheckedEvidence {
            kind,
            digest,
            verified_on_chain: verified,
        });
    }
    Ok(out)
}

/// Check a device's composite signature over `digest` against the hardware
/// key its identity registered on chain: its P-256 key, with its ML-DSA-65
/// key when it registered one (the leg is then required).
fn verify_device_signature(
    state: &dyn VmState,
    device_did: &str,
    digest: &[u8; 32],
    signature: &tenzro_crypto::CompositeSignature,
) -> Result<()> {
    if !matches!(
        signature.classical,
        tenzro_crypto::ClassicalProof::Raw { .. }
    ) {
        return Err(refuse(
            "a reading is signed by the device's hardware key directly",
        ));
    }
    let key = super::registered_identity_key(state, device_did)?;
    tenzro_crypto::verify_composite(
        &key,
        tenzro_crypto::SignatureContext::SensorReading,
        digest,
        signature,
        tenzro_crypto::PqPolicy::WhenPresent,
    )
    .map(|_| ())
    .map_err(|_| refuse(format!("the reading is not signed by {device_did}'s key")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::evidence::DocumentKind;

    #[test]
    fn a_document_is_bound_by_digest_and_a_missing_record_is_refused() {
        let state = crate::StateAdapter::new();
        let checked = check_evidence(
            &state,
            &[Evidence::Document {
                kind: DocumentKind::Delivery,
                digest: [4; 32],
            }],
        )
        .unwrap();
        assert_eq!(checked[0].kind, "delivery");
        assert_eq!(checked[0].digest, [4; 32]);
        assert!(!checked[0].verified_on_chain);
        assert!(
            check_evidence(
                &state,
                &[Evidence::Settlement {
                    payment_id: "p".into()
                }]
            )
            .is_err()
        );
        assert!(
            check_evidence(
                &state,
                &[Evidence::Terms {
                    agent_did: "did:tenzro:agent:x".into()
                }]
            )
            .is_err()
        );
        assert!(check_evidence(&state, &[]).is_err());
    }

    #[test]
    fn a_finality_proof_is_checked_in_the_form_it_carries() {
        let mut state = crate::StateAdapter::new();
        let mut changes = Vec::new();
        set_finality_program(&mut state, &[3; 32], &mut changes).unwrap();
        let item = |stark: Vec<u8>, seal: Vec<u8>| Evidence::FinalityProof {
            journal: vec![0; 13 * 32],
            stark,
            seal,
        };
        let err = |e: Evidence| format!("{:?}", check_evidence(&state, &[e]).unwrap_err());
        assert!(err(item(vec![1; 64], vec![])).contains("STARK"));
        assert!(err(item(vec![], vec![0; 256])).contains("does not verify"));
        assert!(err(item(vec![1; 64], vec![0; 256])).contains("exactly one"));
        assert!(err(item(vec![], vec![])).contains("exactly one"));
    }
}
