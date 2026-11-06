//! Offline verification of an evidence pack (`tenzro_exportEvidencePack`)
//! from the chain's genesis anchor alone. `tenzro agent audit evidence
//! verify` runs it, and so can anyone holding a pack and the anchor.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tenzro_types::evidence_pack::{
    EvidencePack, ProvenRecord, STATE_NAMESPACE, decode_decision, vm_storage_key,
};

use crate::light_client::{Certification, GenesisAnchor};

/// System account of VM storage.
const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];

/// What a verified pack established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Index of the certified checkpoint.
    pub checkpoint: u64,
    /// Audit entries checked against committed roots.
    pub entries: usize,
    /// Chain records checked against the certified state root.
    pub records: usize,
}

/// The part of a commitment record the check reads.
#[derive(serde::Deserialize)]
struct CommittedRoot {
    root: String,
}

/// Check `r` against `root`, whose trie nodes hash under `scheme`, and
/// return the value it proves (`None` for a proven absence).
pub fn check_record(
    scheme: tenzro_types::hash_scheme::HashScheme,
    root: &[u8; 32],
    r: &ProvenRecord,
) -> Result<Option<Vec<u8>>, String> {
    let value = r
        .value
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|_| format!("{} {}: value is not hex", r.kind, r.subject))?;
    let proof: tenzro_storage::StateProof =
        serde_json::from_value(r.proof.clone()).map_err(|e| e.to_string())?;
    let key = vm_storage_key(&SYSTEM_ADDRESS, r.slot.as_bytes());
    // The node hash the pack names. A wrong name cannot pass a forged
    // record: the proof must still hash to the certified root under it.
    tenzro_storage::verify_state_proof(
        scheme,
        root,
        STATE_NAMESPACE,
        &key,
        value.as_deref(),
        &proof,
    )
    .map_err(|e| format!("{} {}: {e}", r.kind, r.subject))?;
    Ok(value)
}

/// Verify `pack` against `anchor` alone, for a checkpoint certified from
/// genesis. A pack certified from a handover chain proof needs
/// [`verify_pack_with`].
pub fn verify_pack(pack: &EvidencePack, anchor: &GenesisAnchor) -> Result<VerifyReport, String> {
    verify_pack_with(pack, anchor, None, |_, _| {
        Err("no handover program verifier is given".to_string())
    })
}

/// Verify `pack` against `anchor`: the checkpoint is certified from genesis
/// (or from a handover chain proof of `handover_program`, checked with
/// `verify_receipt`) and commits the pack's state root, and
/// [`verify_under_root`] holds for that root.
pub fn verify_pack_with<F>(
    pack: &EvidencePack,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
    verify_receipt: F,
) -> Result<VerifyReport, String>
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
    let (entries, records) = verify_under_root(pack, &cp.state_root)?;
    Ok(VerifyReport {
        checkpoint: cp.index,
        entries,
        records,
    })
}

/// Every chain record is proven under `root`, every audit entry reaches the
/// root its node committed on chain, and the manifest matches the sections.
/// Returns the entries and records checked.
pub fn verify_under_root(pack: &EvidencePack, root: &[u8; 32]) -> Result<(usize, usize), String> {
    let mut committed: HashMap<String, String> = HashMap::new();
    for r in &pack.commitments {
        if r.kind != "audit_commit" {
            return Err(format!("a commitment record is a {}", r.kind));
        }
        let value = check_record(pack.state_trie_hash, root, r)?
            .ok_or_else(|| format!("no commitment is recorded for {}", r.subject))?;
        let record: CommittedRoot = serde_json::from_slice(&value).map_err(|e| e.to_string())?;
        committed.insert(r.subject.clone(), record.root);
    }
    for r in pack.oversight.records.iter().chain(&pack.mandate) {
        check_record(pack.state_trie_hash, root, r)?;
    }
    for r in &pack.commerce {
        if r.kind != "payment" {
            return Err(format!("a commerce record is a {}", r.kind));
        }
        let value = check_record(pack.state_trie_hash, root, r)?
            .ok_or_else(|| format!("no payment is recorded at {}", r.subject))?;
        let record: tenzro_types::settlement::PaymentRecord =
            serde_json::from_slice(&value).map_err(|e| e.to_string())?;
        if record.pay_ref != r.subject {
            return Err(format!(
                "the record at {} is payment {}",
                r.subject, record.pay_ref
            ));
        }
        if !record
            .agent_did
            .as_deref()
            .is_some_and(|d| pack.agents.iter().any(|a| a == d))
        {
            return Err(format!(
                "payment {} was not made by an agent the pack covers",
                r.subject
            ));
        }
    }
    for p in &pack.audit {
        let reached = p.verify().map_err(|e| format!("audit entry: {e}"))?;
        let key = format!("{}:{}", p.committer, p.epoch);
        let onchain = committed
            .get(&key)
            .ok_or_else(|| format!("no proven commitment for {key}"))?;
        if *onchain != hex::encode(reached) {
            return Err(format!(
                "an audit entry reaches {}, but {key} committed {onchain}",
                hex::encode(reached)
            ));
        }
    }
    let mut decided = HashMap::new();
    for r in &pack.governance {
        let value = check_record(pack.state_trie_hash, root, r)?;
        match r.kind.as_str() {
            "proposal" => {
                let bytes =
                    value.ok_or_else(|| format!("no proposal {} is recorded", r.subject))?;
                decided.insert(r.subject.clone(), Sha256::digest(&bytes));
            }
            "decision" => {}
            other => return Err(format!("a governance record is a {other}")),
        }
    }
    for r in pack.governance.iter().filter(|r| r.kind == "decision") {
        if let Some(value) = check_record(pack.state_trie_hash, root, r)? {
            let (digest, _) = decode_decision(&value)
                .ok_or_else(|| format!("decision {} is malformed", r.subject))?;
            if decided.get(&r.subject).map(|d| d.as_slice()) != Some(digest.as_slice()) {
                return Err(format!(
                    "decision {} is not of the proposal record the pack carries",
                    r.subject
                ));
            }
        }
    }
    for r in &pack.token_actions {
        if !matches!(r.kind.as_str(), "token_action" | "token_action_count") {
            return Err(format!("a token action record is a {}", r.kind));
        }
        check_record(pack.state_trie_hash, root, r)?;
    }
    if pack.manifest != pack.build_manifest() {
        return Err("the manifest does not match the pack's sections".to_string());
    }
    Ok((
        pack.audit.len(),
        pack.commitments.len()
            + pack.oversight.records.len()
            + pack.mandate.len()
            + pack.commerce.len()
            + pack.governance.len()
            + pack.token_actions.len(),
    ))
}
