//! Offline verification of a trained model's provenance pack
//! ([`tenzro_types::training_provenance`]) from the chain's genesis anchor.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tenzro_crypto::batch::RecordSignature;
use tenzro_types::training_provenance::{
    ROUND_KIND, TRAINER_KIND, TrainedModelReceipt, TrainingProvenancePack,
};
use tenzro_types::training_verification::{TrainingReceipt, training_receipt_slot};

use crate::eu_ai_act::{RegisteredKeyFields, registered_key};
use crate::evidence_pack::check_record;
use crate::light_client::{Certification, GenesisAnchor};

/// The part of a round's record the check reads.
#[derive(Deserialize)]
struct RoundRecord {
    receipt: TrainingReceipt,
    #[serde(default)]
    tee: bool,
    #[serde(default)]
    settled: Option<String>,
}

/// One verified round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRound {
    pub receipt_id: String,
    pub round: u64,
    /// Merkle root over the batches the round trained on.
    pub shard_commitment: String,
    pub start_checkpoint: String,
    pub end_checkpoint: String,
    /// Whether the round's receipt carried a confidential-compute
    /// attestation consensus accepted.
    pub attested: bool,
    /// The milestone escrow released to the trainer.
    pub escrow_id: String,
}

/// What a verified pack established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceReport {
    pub checkpoint: u64,
    pub receipt: TrainedModelReceipt,
    pub rounds: Vec<VerifiedRound>,
}

/// Verify `pack` against `anchor` (or a handover chain proof of
/// `handover_program`, checked with `verify_receipt`): the checkpoint is
/// certified and commits the pack's state root, and
/// [`verify_provenance_under_root`] holds for it.
pub fn verify_provenance<F>(
    pack: &TrainingProvenancePack,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
    verify_receipt: F,
) -> Result<ProvenanceReport, String>
where
    F: FnOnce(&[u8; 32], &[u8]) -> Result<Vec<u8>, String>,
{
    let certification: Certification = serde_json::from_value(pack.checkpoint.clone())
        .map_err(|e| format!("the checkpoint's certification does not decode: {e}"))?;
    let cp = certification
        .verify(anchor, handover_program, verify_receipt)
        .map_err(|e| format!("the checkpoint is not certified: {e}"))?;
    if cp.state_height != pack.state_height || hex::encode(cp.state_root) != pack.state_root {
        return Err(
            "the certified checkpoint commits a different state than the pack names".to_string(),
        );
    }
    let mut report = verify_provenance_under_root(pack, &cp.state_root)?;
    report.checkpoint = cp.index;
    Ok(report)
}

/// The trainer's signature verifies under the identity it registered, every
/// round is proven under `root`, the rounds chain from one end state to the
/// next and end at the receipt's end state, all were trained by the signer,
/// and every milestone was released.
pub fn verify_provenance_under_root(
    pack: &TrainingProvenancePack,
    root: &[u8; 32],
) -> Result<ProvenanceReport, String> {
    let receipt = &pack.receipt.receipt;
    receipt.validate()?;

    let trainer = pack
        .records
        .iter()
        .find(|r| r.kind == TRAINER_KIND && r.subject == receipt.trainer_did)
        .ok_or("the pack does not prove the trainer's identity")?;
    if trainer.slot != tenzro_types::identity::identity_slot(&receipt.trainer_did) {
        return Err("the trainer's identity is proven at another slot".into());
    }
    let value = check_record(pack.state_trie_hash, root, trainer)?
        .ok_or("the trainer has no identity on chain")?;
    let fields: RegisteredKeyFields = serde_json::from_slice(&value).map_err(|e| e.to_string())?;
    if fields.did != receipt.trainer_did {
        return Err("the identity proven is another DID's".into());
    }
    let key = registered_key(
        &fields.did,
        &fields.controller_pubkey,
        &fields.key_type,
        &fields.pq_verifying_key,
    )?;
    let signature: RecordSignature = serde_json::from_slice(&pack.receipt.signature)
        .map_err(|_| "the receipt's signature does not decode".to_string())?;
    signature
        .verify_record_at(&key, &receipt.digest(), receipt.signed_at_ms)
        .map_err(|e| format!("the receipt is not signed by the trainer: {e}"))?;

    let mut rounds = Vec::new();
    let mut previous_end: Option<String> = None;
    let mut previous_round: Option<u64> = None;
    for id in &receipt.rounds {
        let id = id.to_ascii_lowercase();
        let r = pack
            .records
            .iter()
            .find(|r| r.kind == ROUND_KIND && r.subject.to_ascii_lowercase() == id)
            .ok_or_else(|| format!("round {id} is not proven by the pack"))?;
        if r.slot != training_receipt_slot(&id) {
            return Err(format!("round {id} is proven at another slot"));
        }
        let value = check_record(pack.state_trie_hash, root, r)?
            .ok_or_else(|| format!("no round {id} is committed on chain"))?;
        let record: RoundRecord =
            serde_json::from_slice(&value).map_err(|e| format!("round {id}: {e}"))?;
        let t = &record.receipt;
        if t.receipt_id() != id {
            return Err(format!(
                "the record at round {id} is round {}",
                t.receipt_id()
            ));
        }
        if t.trainer_did != receipt.trainer_did {
            return Err(format!("round {id} was trained by {}", t.trainer_did));
        }
        if record.settled.as_deref() != Some("released") {
            return Err(format!(
                "the milestone of round {id} was not released ({})",
                record.settled.as_deref().unwrap_or("not settled")
            ));
        }
        if let Some(end) = &previous_end
            && !end.eq_ignore_ascii_case(&t.start_checkpoint)
        {
            return Err(format!(
                "round {id} does not start where the round before it ended"
            ));
        }
        if previous_round.is_some_and(|p| t.round <= p) {
            return Err(format!("round {id} is out of order"));
        }
        previous_end = Some(t.end_checkpoint.clone());
        previous_round = Some(t.round);
        rounds.push(VerifiedRound {
            receipt_id: id,
            round: t.round,
            shard_commitment: t.shard_commitment.clone(),
            start_checkpoint: t.start_checkpoint.clone(),
            end_checkpoint: t.end_checkpoint.clone(),
            attested: record.tee,
            escrow_id: t.escrow_id.clone(),
        });
    }
    if !previous_end.is_some_and(|e| e.eq_ignore_ascii_case(&receipt.end_checkpoint)) {
        return Err("the last round does not end at the state the receipt names".into());
    }
    Ok(ProvenanceReport {
        checkpoint: 0,
        receipt: receipt.clone(),
        rounds,
    })
}

/// Whether `weights` are the weights the receipt names.
pub fn weights_match(receipt: &TrainedModelReceipt, weights: &[u8]) -> bool {
    hex::encode(Sha256::digest(weights))
        .eq_ignore_ascii_case(receipt.output_sha256.trim_start_matches("0x"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tenzro_crypto::batch::RecordSigner;
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::evidence_pack::{ProvenRecord, STATE_NAMESPACE, vm_storage_key};
    use tenzro_types::training_provenance::SignedTrainedModelReceipt;

    const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

    fn round(trainer: &str, n: u64, start: u8, end: u8) -> TrainingReceipt {
        TrainingReceipt {
            escrow_id: hex::encode([0x40 + n as u8; 32]),
            trainer_did: trainer.into(),
            round: n,
            start_checkpoint: hex::encode([start; 32]),
            shard_commitment: hex::encode([0x50 + n as u8; 32]),
            hyperparameters: hex::encode([0x60; 32]),
            steps: 8,
            end_checkpoint: hex::encode([end; 32]),
            step_root: hex::encode([0x70 + n as u8; 32]),
            kernel_class: "sm_121".into(),
            signed_at_ms: 1_000 + n,
        }
    }

    /// A pack for a two-round job whose rounds were released, under a real
    /// state root, and the weights it names.
    fn pack(settled: [&str; 2]) -> (TrainingProvenancePack, [u8; 32], Vec<u8>) {
        let signer = crate::eu_ai_act::fixture::node_signer();
        let did = crate::eu_ai_act::fixture::node_did(&signer);
        let rounds = [round(&did, 0, 1, 2), round(&did, 1, 2, 3)];
        let weights = b"adapter weights".to_vec();
        let receipt = TrainedModelReceipt {
            model_id: "qwen3-0.6b".into(),
            base_sha256: hex::encode([9; 32]),
            output_sha256: hex::encode(Sha256::digest(&weights)),
            trainer_did: did.clone(),
            rounds: rounds.iter().map(|r| r.receipt_id()).collect(),
            end_checkpoint: hex::encode([3; 32]),
            signed_at_ms: tenzro_crypto::session::now_ms(),
        };
        let sig = signer.sign_record(&receipt.digest()).unwrap();
        let mut key = vec![0x04];
        key.extend_from_slice(&signer.identity().p256);
        let mut slots = vec![(
            tenzro_types::identity::identity_slot(&did),
            serde_json::json!({ "did": did, "controller_pubkey": key, "key_type": "p256" }),
        )];
        for (r, s) in rounds.iter().zip(settled) {
            slots.push((
                training_receipt_slot(&r.receipt_id()),
                serde_json::json!({
                    "receipt": r, "committed_at_ms": 1, "window_ms": 10, "tee": r.round == 1,
                    "trainer_account": "aa", "challenges": [], "settled": s,
                }),
            ));
        }
        let trie = StateTrie::new(Arc::new(MemoryStore::new()));
        let mut writes = Writes::new();
        for (slot, value) in &slots {
            writes.insert(
                (
                    STATE_NAMESPACE.to_string(),
                    vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                ),
                Some(serde_json::to_vec(value).unwrap()),
            );
        }
        let root = trie.commit(1, &writes).unwrap();
        let record = |kind: &str, subject: &str, slot: &str| {
            let (value, proof) = trie
                .prove(
                    1,
                    STATE_NAMESPACE,
                    &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                )
                .unwrap();
            ProvenRecord {
                kind: kind.into(),
                subject: subject.into(),
                slot: slot.into(),
                value: value.map(hex::encode),
                proof: serde_json::to_value(proof).unwrap(),
            }
        };
        let mut records = vec![record(TRAINER_KIND, &did, &slots[0].0)];
        for r in &rounds {
            let id = r.receipt_id();
            records.push(record(ROUND_KIND, &id, &training_receipt_slot(&id)));
        }
        (
            TrainingProvenancePack {
                receipt: SignedTrainedModelReceipt {
                    receipt,
                    signature: serde_json::to_vec(&sig).unwrap(),
                },
                state_height: 1,
                state_root: hex::encode(root.as_bytes()),
                state_trie_hash: trie.scheme_at(1).unwrap(),
                checkpoint: serde_json::Value::Null,
                records,
            },
            root.as_bytes().try_into().unwrap(),
            weights,
        )
    }

    #[test]
    fn a_released_job_proves_where_its_weights_came_from() {
        let (p, root, weights) = pack(["released", "released"]);
        let report = verify_provenance_under_root(&p, &root).unwrap();
        assert_eq!(report.rounds.len(), 2);
        assert_eq!(
            report.rounds.iter().map(|r| r.attested).collect::<Vec<_>>(),
            vec![false, true]
        );
        assert_eq!(report.rounds[0].shard_commitment, hex::encode([0x50; 32]));
        assert!(weights_match(&report.receipt, &weights));
        assert!(!weights_match(&report.receipt, b"other weights"));
    }

    #[test]
    fn every_broken_link_is_refused() {
        let (p, root, _) = pack(["released", "released"]);
        assert!(
            verify_provenance_under_root(&p, &[7; 32]).is_err(),
            "another root"
        );

        let (v, root_v, _) = pack(["released", "voided"]);
        assert!(
            verify_provenance_under_root(&v, &root_v).is_err(),
            "a voided milestone"
        );

        let mut q = p.clone();
        q.receipt.receipt.output_sha256 = hex::encode([1; 32]);
        assert!(
            verify_provenance_under_root(&q, &root).is_err(),
            "changed weights hash"
        );

        let mut q = p.clone();
        q.receipt.receipt.rounds.reverse();
        assert!(
            verify_provenance_under_root(&q, &root).is_err(),
            "rounds out of order"
        );

        let mut q = p.clone();
        q.receipt.receipt.rounds.pop();
        assert!(
            verify_provenance_under_root(&q, &root).is_err(),
            "a dropped round"
        );

        let mut q = p.clone();
        q.records.retain(|r| r.kind != TRAINER_KIND);
        assert!(
            verify_provenance_under_root(&q, &root).is_err(),
            "no trainer identity"
        );

        let mut q = p.clone();
        let other = {
            let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
                Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(30));
            tenzro_crypto::batch::ImmediateRecordSigner::new(id)
        };
        q.receipt.signature =
            serde_json::to_vec(&other.sign_record(&q.receipt.receipt.digest()).unwrap()).unwrap();
        assert!(
            verify_provenance_under_root(&q, &root).is_err(),
            "signed by another key"
        );
    }
}
