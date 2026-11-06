//! `tenzro agent audit evidence`: export a compliance and dispute evidence
//! pack, and verify one offline against the chain's genesis anchor.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tenzro_consensus::Checkpoint;
use tenzro_consensus::light_client::{Certification, GenesisAnchor};
use tenzro_types::evidence_pack::{EvidencePack, GovernanceReceipt, ProvenRecord, decode_decision};

use crate::output;

/// Evidence packs.
#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// Export the pack for one agent, or for every agent of a root identity
    Export(EvidenceExportCmd),
    /// Verify a pack offline against the chain's genesis anchor
    Verify(EvidenceVerifyCmd),
    /// Write the EU AI Act profile of a pack: which records support Art. 12
    /// and Art. 14, what each proves and what it does not
    Profile(EvidenceProfileCmd),
    /// Check evidence items against chain state (`tenzro_verifyEvidence`)
    Check(EvidenceCheckCmd),
}

impl EvidenceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Export(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute(),
            Self::Profile(cmd) => cmd.execute(),
            Self::Check(cmd) => cmd.execute().await,
        }
    }
}

/// Check evidence items against chain state: audit entries against their
/// committed roots, agent terms, recorded settlements, device-signed
/// readings, finality proofs. Documents are bound by digest only.
#[derive(Debug, Parser)]
pub struct EvidenceCheckCmd {
    /// A JSON file holding the list of evidence items
    #[arg(long)]
    items: PathBuf,
    /// RPC endpoint of a node that follows the chain
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EvidenceCheckCmd {
    pub async fn execute(&self) -> Result<()> {
        let items: Vec<tenzro_types::evidence::Evidence> =
            serde_json::from_slice(&std::fs::read(&self.items)?)?;
        tenzro_types::evidence::Evidence::validate(&items).map_err(|e| anyhow!(e))?;
        let result: serde_json::Value = crate::rpc::RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyEvidence",
                serde_json::json!({ "items": items }),
            )
            .await?;
        output::print_header("Evidence");
        for item in result
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let field = |k: &str| {
                item.get(k)
                    .map(|v| v.to_string().trim_matches('"').to_string())
                    .unwrap_or_default()
            };
            output::print_field(
                &field("kind"),
                &format!(
                    "{} (checked on chain: {})",
                    field("digest"),
                    field("verified_on_chain")
                ),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EvidenceExportCmd {
    /// The agent
    #[arg(long, conflicts_with = "root")]
    agent: Option<String>,
    /// A root identity: its agents named with --covers or in the audit file
    #[arg(long)]
    root: Option<String>,
    /// An agent of --root to cover; repeat for each
    #[arg(long = "covers")]
    agents: Vec<String>,
    /// File holding the audit entry proofs from the agents' recorder (JSON
    /// array)
    #[arg(long)]
    audit: Option<PathBuf>,
    /// File holding the agents' signed session receipts (JSON array)
    #[arg(long)]
    receipts: Option<PathBuf>,
    /// A payment the covered agents made (pay_ref hex), proven into the
    /// pack's commerce section; repeat for each
    #[arg(long = "payment")]
    payments: Vec<String>,
    /// A governance proposal touching the subject (64 hex), proven into the
    /// governance section with its decision; repeat for each
    #[arg(long = "proposal")]
    proposals: Vec<String>,
    /// A token the covered agents held (64 hex): its issuer actions are
    /// proven into the token_actions section; repeat for each
    #[arg(long = "token")]
    tokens: Vec<String>,
    /// Where to write the pack
    #[arg(long)]
    out: PathBuf,
    /// RPC endpoint of a node that follows the chain
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EvidenceExportCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut params = match (&self.agent, &self.root) {
            (Some(a), None) => serde_json::json!({ "agent_did": a }),
            (None, Some(r)) => serde_json::json!({ "root_did": r }),
            _ => bail!("give --agent or --root"),
        };
        if !self.agents.is_empty() {
            params["agents"] = serde_json::json!(self.agents);
        }
        if let Some(f) = &self.audit {
            params["audit"] = serde_json::from_slice(&std::fs::read(f)?)?;
        }
        if let Some(f) = &self.receipts {
            params["receipts"] = serde_json::from_slice(&std::fs::read(f)?)?;
        }
        if !self.payments.is_empty() {
            params["payments"] = serde_json::json!(self.payments);
        }
        for (key, items) in [("proposals", &self.proposals), ("tokens", &self.tokens)] {
            if !items.is_empty() {
                params[key] = serde_json::json!(items);
            }
        }
        let pack: serde_json::Value = crate::rpc::RpcClient::new(&self.rpc)
            .call("tenzro_exportEvidencePack", params)
            .await?;
        std::fs::write(&self.out, serde_json::to_vec_pretty(&pack)?)?;
        output::print_header("Evidence pack exported");
        output::print_field("File", &self.out.display().to_string());
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EvidenceVerifyCmd {
    /// The pack
    #[arg(long)]
    file: PathBuf,
    /// Chain id, from the genesis file
    #[arg(long)]
    chain_id: u64,
    /// Genesis block hash, hex
    #[arg(long)]
    genesis_hash: String,
    /// Root of the genesis committee, hex
    #[arg(long)]
    genesis_committee_root: String,
    /// Image id of the handover program, hex, from the chain's governance:
    /// needed when the pack's checkpoint is certified from a handover chain
    /// proof
    #[arg(long)]
    handover_program: Option<String>,
    /// An EU AI Act profile of the pack (`evidence profile`) to check too:
    /// every node-signed tool-call record against its node's registered
    /// identity, and the profile against the pack it names
    #[arg(long)]
    profile: Option<PathBuf>,
}

/// Build the EU AI Act profile of a pack. The profile is checked, with the
/// pack, by `evidence verify --profile`.
#[derive(Debug, Parser)]
pub struct EvidenceProfileCmd {
    /// The pack
    #[arg(long)]
    file: PathBuf,
    /// Where to write the profile; printed when absent
    #[arg(long)]
    out: Option<PathBuf>,
}

impl EvidenceProfileCmd {
    pub fn execute(&self) -> Result<()> {
        let pack: EvidencePack = serde_json::from_slice(&std::fs::read(&self.file)?)?;
        let profile = tenzro_consensus::eu_ai_act::build_profile(&pack);
        let json = serde_json::to_string_pretty(&profile)?;
        match &self.out {
            Some(path) => std::fs::write(path, json + "\n")?,
            None => println!("{json}"),
        }
        Ok(())
    }
}

/// Verify `pack` and its EU AI Act `profile` against `anchor` alone.
pub fn verify_profile(
    pack: &EvidencePack,
    profile: &tenzro_consensus::eu_ai_act::Profile,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
) -> Result<tenzro_consensus::eu_ai_act::ProfileReport> {
    tenzro_consensus::eu_ai_act::verify_profile(
        pack,
        profile,
        anchor,
        handover_program,
        tenzro_zk::handover_chain::verify_receipt,
    )
    .map_err(|e| anyhow!(e))
}

pub(crate) fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("{what} is not 32 bytes of hex"))
}

impl EvidenceVerifyCmd {
    pub fn execute(&self) -> Result<()> {
        let pack: EvidencePack = serde_json::from_slice(&std::fs::read(&self.file)?)?;
        let anchor = GenesisAnchor {
            chain_id: self.chain_id,
            genesis_hash: hex32(&self.genesis_hash, "--genesis-hash")?,
            committee_root: hex32(&self.genesis_committee_root, "--genesis-committee-root")?,
        };
        let program = self
            .handover_program
            .as_deref()
            .map(|h| hex32(h, "--handover-program"))
            .transpose()?;
        if let Some(path) = &self.profile {
            let profile: tenzro_consensus::eu_ai_act::Profile =
                serde_json::from_slice(&std::fs::read(path)?)?;
            let report = verify_profile(&pack, &profile, &anchor, program)?;
            output::print_header("Evidence pack and EU AI Act profile verified");
            output::print_field("Subject", &pack.subject);
            output::print_field("Certified checkpoint", &report.pack.checkpoint.to_string());
            output::print_field("State height", &pack.state_height.to_string());
            output::print_field("Audit entries", &report.pack.entries.to_string());
            output::print_field("Chain records", &report.pack.records.to_string());
            output::print_field(
                "Node-signed tool calls",
                &report.signed_tool_calls.to_string(),
            );
            for c in &profile.clauses {
                output::print_field(
                    &format!("{} {}", c.id, c.measure),
                    &format!("{} items", c.evidence.len()),
                );
                println!("    {}", c.requirement);
                println!("    Proves: {}", c.proves);
                println!("    Does not prove: {}", c.does_not_prove);
            }
            return Ok(());
        }
        let report = verify_pack(&pack, &anchor, program)?;
        output::print_header("Evidence pack verified");
        output::print_field("Subject", &pack.subject);
        output::print_field("Agents", &pack.agents.join(", "));
        output::print_field("Certified checkpoint", &report.checkpoint.to_string());
        output::print_field("State height", &pack.state_height.to_string());
        output::print_field("State trie hash", &format!("{:?}", pack.state_trie_hash));
        output::print_field("Audit entries", &report.entries.to_string());
        output::print_field("Chain records", &report.records.to_string());
        for s in &pack.manifest {
            output::print_field(&s.section, &s.controls.join(", "));
        }
        Ok(())
    }
}

pub use tenzro_consensus::evidence_pack::VerifyReport;

fn check_record(
    scheme: tenzro_types::hash_scheme::HashScheme,
    root: &[u8; 32],
    r: &ProvenRecord,
) -> Result<Option<Vec<u8>>> {
    tenzro_consensus::evidence_pack::check_record(scheme, root, r).map_err(|e| anyhow!(e))
}

/// The checkpoint `certification` (JSON) certifies from `anchor`: walked
/// from genesis, or from a handover chain proof of `handover_program`.
pub fn certified_checkpoint(
    certification: &serde_json::Value,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
) -> Result<Checkpoint> {
    let certification: Certification = serde_json::from_value(certification.clone())
        .map_err(|e| anyhow!("the checkpoint's certification does not decode: {e}"))?;
    certification
        .verify(
            anchor,
            handover_program,
            tenzro_zk::handover_chain::verify_receipt,
        )
        .cloned()
        .map_err(|e| anyhow!("the checkpoint is not certified: {e}"))
}

/// Verify `pack` against `anchor` alone: the checkpoint is certified from
/// genesis (or from a handover chain proof of `handover_program`) and
/// commits the pack's state root, and [`verify_under_root`] holds for that
/// root.
pub fn verify_pack(
    pack: &EvidencePack,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
) -> Result<VerifyReport> {
    tenzro_consensus::evidence_pack::verify_pack_with(
        pack,
        anchor,
        handover_program,
        tenzro_zk::handover_chain::verify_receipt,
    )
    .map_err(|e| anyhow!(e))
}

/// Every chain record is proven under `root`, every audit entry reaches the
/// root its node committed on chain, and the manifest matches the sections.
/// Returns the entries and records checked.
pub fn verify_under_root(pack: &EvidencePack, root: &[u8; 32]) -> Result<(usize, usize)> {
    tenzro_consensus::evidence_pack::verify_under_root(pack, root).map_err(|e| anyhow!(e))
}

/// What a verified governance receipt establishes, read from its proven
/// records only.
#[derive(Debug)]
pub struct ReceiptReport {
    /// Index of the certified checkpoint.
    pub checkpoint: u64,
    /// The proposal record, as consensus stores it.
    pub proposal: serde_json::Value,
    /// The tally record, if a vote was cast.
    pub tally: Option<serde_json::Value>,
    /// TNZO locked in the veto escrow, base units.
    pub veto_locked: u128,
    /// Height the proposal was enacted at, if it was.
    pub executed_height: Option<u64>,
    /// The scheduled activation, for an enacted protocol upgrade.
    pub activation: Option<serde_json::Value>,
}

/// Verify `receipt` against `anchor` alone: the checkpoint is certified from
/// genesis (or from a handover chain proof of `handover_program`) and
/// commits the receipt's state root, and [`verify_receipt_under_root`] holds
/// for that root.
pub fn verify_governance_receipt(
    receipt: &GovernanceReceipt,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
) -> Result<ReceiptReport> {
    let cp = certified_checkpoint(&receipt.checkpoint, anchor, handover_program)?;
    if cp.state_height != receipt.state_height || hex::encode(cp.state_root) != receipt.state_root {
        bail!("the certified checkpoint commits a different state than the receipt names");
    }
    let mut report = verify_receipt_under_root(receipt, &cp.state_root)?;
    report.checkpoint = cp.index;
    Ok(report)
}

/// Every record of `receipt` is proven under `root` and about its proposal,
/// and a decision record is of exactly the proposal record proven beside it.
pub fn verify_receipt_under_root(
    receipt: &GovernanceReceipt,
    root: &[u8; 32],
) -> Result<ReceiptReport> {
    let mut values: HashMap<&str, Option<Vec<u8>>> = HashMap::new();
    for r in &receipt.records {
        if r.subject != receipt.proposal_id {
            bail!(
                "a {} record is about {}, not {}",
                r.kind,
                r.subject,
                receipt.proposal_id
            );
        }
        if values
            .insert(
                r.kind.as_str(),
                check_record(receipt.state_trie_hash, root, r)?,
            )
            .is_some()
        {
            bail!("the receipt carries two {} records", r.kind);
        }
    }
    let proposal_bytes = values
        .get("proposal")
        .cloned()
        .flatten()
        .ok_or_else(|| anyhow!("the receipt proves no proposal record"))?;
    let proposal: serde_json::Value = serde_json::from_slice(&proposal_bytes)?;
    if proposal["id"].as_str() != Some(receipt.proposal_id.as_str()) {
        bail!("the proposal record is of another proposal");
    }
    for kind in ["tally", "veto_total", "decision"] {
        if !values.contains_key(kind) {
            bail!("the receipt does not prove the {kind} record");
        }
    }
    let executed_height = match values.get("decision").cloned().flatten() {
        Some(v) => {
            let (digest, height) =
                decode_decision(&v).ok_or_else(|| anyhow!("the decision record is malformed"))?;
            if digest.as_slice() != Sha256::digest(&proposal_bytes).as_slice() {
                bail!("the decision record is not of the proven proposal record");
            }
            if proposal["status"] != "executed" {
                bail!("a decision is recorded for a proposal that is not executed");
            }
            Some(height)
        }
        None => None,
    };
    let json = |k: &str| {
        values
            .get(k)
            .cloned()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
    };
    let veto_locked = values
        .get("veto_total")
        .cloned()
        .flatten()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(u128::from_le_bytes)
        .unwrap_or(0);
    Ok(ReceiptReport {
        checkpoint: 0,
        tally: json("tally"),
        activation: json("activation"),
        proposal,
        veto_locked,
        executed_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::evidence_pack::{STATE_NAMESPACE, vm_storage_key};

    /// System account of VM storage.
    const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];
    use std::sync::Arc;
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::agent_audit::{
        ActionKind, ActionOutcome, AuditEntry, AuditProof, Mmr, SessionLeaf, SignedAuditEntry,
        epoch_root, prove_epoch,
    };
    use tenzro_types::evidence_pack::{Jurisdiction, Oversight};

    const COMMITTER: &str = "0xaa";

    fn entry(seq: u64, prev: [u8; 32]) -> SignedAuditEntry {
        let e = AuditEntry {
            session_id: [3; 32],
            seq,
            at_ms: 1_000 + seq,
            agent: "did:tenzro:machine:alice:bot".into(),
            kind: if seq == 0 {
                ActionKind::Approval
            } else {
                ActionKind::Spend
            },
            action: "checkout".into(),
            outcome: ActionOutcome::Allowed,
            detail: [seq as u8; 32],
            linked_tx: None,
            prev,
            image: None,
            call: None,
        };
        SignedAuditEntry {
            body: serde_json::to_vec(&e).unwrap(),
            signature: vec![],
        }
    }

    const PAY_REF: [u8; 32] = [0x77; 32];
    const PAY_SLOT: &str = "pay:7777777777777777777777777777777777777777777777777777777777777777";

    fn payment() -> tenzro_types::settlement::PaymentRecord {
        tenzro_types::settlement::PaymentRecord {
            pay_ref: hex::encode(PAY_REF),
            class: tenzro_types::settlement::RecordClass::Native,
            payer: hex::encode([1; 32]),
            payee: tenzro_types::Address::new([2; 32]),
            asset: "TNZO".into(),
            amount: 5,
            fee: 1,
            settled: Default::default(),
            binding: Default::default(),
            nonce: "pay-1".into(),
            agent_did: Some("did:tenzro:machine:alice:bot".into()),
            source: None,
            attestor: None,
            receipts: vec![],
            refunded: 0,
            recorded_at_ms: 1,
        }
    }

    const PROPOSAL: &str = "abababababababababababababababababababababababababababababababab";

    fn proposal_record() -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({ "id": PROPOSAL, "status": "executed", "track": "standard" }),
        )
        .unwrap()
    }

    /// An executed proposal's records: the proposal, its tally, an empty
    /// veto escrow and its decision at height 7.
    fn governance_slots() -> Vec<(String, Option<Vec<u8>>)> {
        let mut decision = Sha256::digest(proposal_record()).to_vec();
        decision.extend_from_slice(&7u64.to_be_bytes());
        vec![
            (format!("proposal:{PROPOSAL}"), Some(proposal_record())),
            (
                format!("proposal_tally:{PROPOSAL}"),
                Some(br#"{"yes":"3","no":"1","total_eligible":"4"}"#.to_vec()),
            ),
            (format!("governance_decision:{PROPOSAL}"), Some(decision)),
        ]
    }

    /// The receipt of the executed proposal under the pack's state root.
    fn receipt() -> (GovernanceReceipt, [u8; 32]) {
        let trie = StateTrie::new(Arc::new(MemoryStore::new()));
        let mut writes = Writes::new();
        for (slot, value) in governance_slots() {
            writes.insert(
                (
                    STATE_NAMESPACE.to_string(),
                    vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                ),
                value,
            );
        }
        let state_root = trie.commit(1, &writes).unwrap();
        let records = [
            ("proposal", format!("proposal:{PROPOSAL}")),
            ("tally", format!("proposal_tally:{PROPOSAL}")),
            ("veto_total", format!("veto_total:{PROPOSAL}")),
            ("decision", format!("governance_decision:{PROPOSAL}")),
        ]
        .into_iter()
        .map(|(kind, slot)| {
            let key = vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes());
            let (value, proof) = trie.prove(1, STATE_NAMESPACE, &key).unwrap();
            ProvenRecord {
                kind: kind.into(),
                subject: PROPOSAL.into(),
                slot,
                value: value.map(hex::encode),
                proof: serde_json::to_value(proof).unwrap(),
            }
        })
        .collect();
        (
            GovernanceReceipt {
                proposal_id: PROPOSAL.into(),
                state_height: 1,
                state_root: hex::encode(state_root.as_bytes()),
                state_trie_hash: trie.scheme_at(1).unwrap(),
                checkpoint: serde_json::Value::Null,
                records,
            },
            state_root.as_bytes().try_into().unwrap(),
        )
    }

    /// The receipt of `receipt()` proven at height 2, after the state trie
    /// switched its node hash to SHA3-256 at that height.
    fn receipt_after_switch() -> (GovernanceReceipt, [u8; 32]) {
        let trie = StateTrie::new(Arc::new(MemoryStore::new()));
        let mut writes = Writes::new();
        for (slot, value) in governance_slots() {
            writes.insert(
                (
                    STATE_NAMESPACE.to_string(),
                    vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                ),
                value,
            );
        }
        trie.commit(1, &writes).unwrap();
        let state_root = trie
            .recommit_under(2, tenzro_types::hash_scheme::HashScheme::Sha3_256)
            .unwrap();
        let (mut receipt, _) = receipt();
        for r in &mut receipt.records {
            let key = vm_storage_key(&SYSTEM_ADDRESS, r.slot.as_bytes());
            let (value, proof) = trie.prove(2, STATE_NAMESPACE, &key).unwrap();
            r.value = value.map(hex::encode);
            r.proof = serde_json::to_value(proof).unwrap();
        }
        receipt.state_height = 2;
        receipt.state_root = hex::encode(state_root.as_bytes());
        receipt.state_trie_hash = trie.scheme_at(2).unwrap();
        (receipt, state_root.as_bytes().try_into().unwrap())
    }

    /// Records of a state hashed under SHA3-256 after a switch verify under
    /// the scheme the receipt names.
    #[test]
    fn a_receipt_of_a_state_after_a_hash_switch_verifies() {
        let (receipt, root) = receipt_after_switch();
        assert_eq!(
            receipt.state_trie_hash,
            tenzro_types::hash_scheme::HashScheme::Sha3_256
        );
        let report = verify_receipt_under_root(&receipt, &root).unwrap();
        assert_eq!(report.executed_height, Some(7));

        // Named as SHA-256 the same proofs do not reach the root.
        let mut r = receipt.clone();
        r.state_trie_hash = tenzro_types::hash_scheme::HashScheme::Sha256;
        assert!(verify_receipt_under_root(&r, &root).is_err());
        // A pack made before the hash was named reads as SHA-256.
        let mut v = serde_json::to_value(&receipt).unwrap();
        v.as_object_mut().unwrap().remove("state_trie_hash");
        let old: GovernanceReceipt = serde_json::from_value(v).unwrap();
        assert_eq!(
            old.state_trie_hash,
            tenzro_types::hash_scheme::HashScheme::Sha256
        );
    }

    #[test]
    fn a_receipt_verifies_and_a_tampered_tally_or_decision_does_not() {
        let (receipt, root) = receipt();
        let report = verify_receipt_under_root(&receipt, &root).unwrap();
        assert_eq!(report.executed_height, Some(7));
        assert_eq!(report.tally.unwrap()["yes"], "3");
        assert_eq!(report.veto_locked, 0);

        let mut r = receipt.clone();
        let tally = r.records.iter_mut().find(|x| x.kind == "tally").unwrap();
        tally.value = Some(hex::encode(br#"{"yes":"4","no":"0","total_eligible":"4"}"#));
        assert!(
            verify_receipt_under_root(&r, &root).is_err(),
            "a tampered tally fails"
        );

        let mut r = receipt.clone();
        r.records.retain(|x| x.kind != "decision");
        assert!(
            verify_receipt_under_root(&r, &root).is_err(),
            "every record is proven, absent or not"
        );

        let mut r = receipt.clone();
        r.records[0].subject = "cd".repeat(32);
        assert!(verify_receipt_under_root(&r, &root).is_err());
        assert!(verify_receipt_under_root(&receipt, &[9; 32]).is_err());
    }

    /// A pack whose two entries reach an epoch root that chain state, proven
    /// under a real state root, records for the committer.
    fn pack() -> (EvidencePack, [u8; 32]) {
        let first = entry(0, [0; 32]);
        let second = entry(1, first.leaf_hash());
        let mmr = Mmr::from_leaves([first.leaf_hash(), second.leaf_hash()]);
        let leaf = SessionLeaf {
            session_id: [3; 32],
            mmr_root: mmr.root(),
            count: 2,
        };
        let leaves = vec![leaf];
        let root_hex = hex::encode(epoch_root(&leaves));
        let audit: Vec<AuditProof> = [first, second]
            .into_iter()
            .enumerate()
            .map(|(i, e)| AuditProof {
                entry: e,
                mmr: mmr.prove(i as u64, 2).unwrap(),
                epoch_proof: prove_epoch(&leaves, &[3; 32]).unwrap(),
                epoch: 4,
                committer: COMMITTER.into(),
            })
            .collect();

        let slots = [
            (
                "agent_audit:aa:0000000000000004",
                serde_json::json!({ "root": root_hex, "sessions": 1 }),
            ),
            (
                "agent_terms:did:tenzro:machine:alice:bot",
                serde_json::json!({ "version": 1 }),
            ),
            (PAY_SLOT, serde_json::to_value(payment()).unwrap()),
            (
                "token_action:aa:0",
                serde_json::json!({ "kind": "frozen", "at_ms": 1 }),
            ),
        ];
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
        for (slot, value) in governance_slots() {
            writes.insert(
                (
                    STATE_NAMESPACE.to_string(),
                    vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                ),
                value,
            );
        }
        let state_root = trie.commit(1, &writes).unwrap();
        let record = |kind: &str, subject: &str, slot: &str| {
            let key = vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes());
            let (value, proof) = trie.prove(1, STATE_NAMESPACE, &key).unwrap();
            ProvenRecord {
                kind: kind.into(),
                subject: subject.into(),
                slot: slot.into(),
                value: value.map(hex::encode),
                proof: serde_json::to_value(proof).unwrap(),
            }
        };
        let mut pack = EvidencePack {
            subject: "did:tenzro:machine:alice:bot".into(),
            agents: vec!["did:tenzro:machine:alice:bot".into()],
            generated_at_ms: 0,
            state_height: 1,
            state_root: hex::encode(state_root.as_bytes()),
            state_trie_hash: trie.scheme_at(1).unwrap(),
            checkpoint: serde_json::Value::Null,
            audit,
            commitments: vec![record("audit_commit", "0xaa:4", slots[0].0)],
            oversight: Oversight {
                records: vec![record(
                    "quarantine",
                    "did:tenzro:machine:alice:bot",
                    "agent_quarantine:did:tenzro:machine:alice:bot",
                )],
                actions: vec![(hex::encode([3; 32]), 0)],
            },
            mandate: vec![record("terms", "did:tenzro:machine:alice:bot", slots[1].0)],
            commerce: vec![record("payment", &hex::encode(PAY_REF), PAY_SLOT)],
            governance: vec![
                record("proposal", PROPOSAL, &format!("proposal:{PROPOSAL}")),
                record(
                    "decision",
                    PROPOSAL,
                    &format!("governance_decision:{PROPOSAL}"),
                ),
            ],
            token_actions: vec![record("token_action", "aa:0", "token_action:aa:0")],
            receipts: vec![],
            models: vec![],
            jurisdiction: Jurisdiction {
                country: Some("DE".into()),
                blocs: vec!["EU".into()],
            },
            manifest: vec![],
        };
        pack.manifest = pack.build_manifest();
        (pack, state_root.as_bytes().try_into().unwrap())
    }

    #[test]
    fn a_pack_verifies_under_its_root_and_every_tampering_is_refused() {
        let (pack, root) = pack();
        assert_eq!(verify_under_root(&pack, &root).unwrap(), (2, 7));

        // A decision stands only for the proposal record proven beside it.
        let mut p = pack.clone();
        p.governance.retain(|r| r.kind != "proposal");
        p.manifest = p.build_manifest();
        assert!(verify_under_root(&p, &root).is_err());
        // The new sections are covered by the manifest.
        let mut p = pack.clone();
        p.token_actions.clear();
        assert!(verify_under_root(&p, &root).is_err());
        let mut p = pack.clone();
        p.token_actions[0].kind = "payment".into();
        p.manifest = p.build_manifest();
        assert!(verify_under_root(&p, &root).is_err());

        // A payment record stands only for the reference it is proven at,
        // and only for an agent the pack covers.
        let mut p = pack.clone();
        p.commerce[0].subject = hex::encode([0x78; 32]);
        assert!(verify_under_root(&p, &root).is_err());
        let mut p = pack.clone();
        p.agents = vec!["did:tenzro:machine:alice:other".into()];
        assert!(verify_under_root(&p, &root).is_err());

        // Another root: no record proves.
        assert!(verify_under_root(&pack, &[9; 32]).is_err());

        // A changed entry no longer reaches the committed root.
        let mut p = pack.clone();
        p.audit[1].entry = entry(1, [7; 32]);
        assert!(verify_under_root(&p, &root).is_err());

        // A changed chain record no longer matches its proof.
        let mut p = pack.clone();
        p.mandate[0].value = Some(hex::encode(br#"{"version":2}"#));
        assert!(verify_under_root(&p, &root).is_err());

        // A quarantine hidden by claiming the slot is empty fails too: the
        // slot is proven absent here, so claim a value instead.
        let mut p = pack.clone();
        p.oversight.records[0].value = Some(hex::encode(b"{}"));
        assert!(verify_under_root(&p, &root).is_err());

        // Entries without their commitment, or a stale manifest, are refused.
        let mut p = pack.clone();
        p.commitments.clear();
        p.manifest = p.build_manifest();
        assert!(verify_under_root(&p, &root).is_err());
        let mut p = pack.clone();
        p.jurisdiction.country = Some("US".into());
        assert!(verify_under_root(&p, &root).is_err());
    }

    /// The EU AI Act fixture (`tenzro-consensus` writes it): a pack with
    /// node-signed tool-call records and its profile, verified from the
    /// genesis anchor alone, as an auditor runs it; the profile is also
    /// rebuilt from the pack, as `evidence profile` writes it.
    #[test]
    fn the_eu_ai_act_profile_verifies_offline_from_the_genesis_anchor() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/eu_ai_act/pack_from_genesis.json");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let anchor = GenesisAnchor {
            chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
            genesis_hash: hex32(fixture["anchor"]["genesis_hash"].as_str().unwrap(), "g").unwrap(),
            committee_root: hex32(fixture["anchor"]["committee_root"].as_str().unwrap(), "c")
                .unwrap(),
        };
        let pack: EvidencePack = serde_json::from_value(fixture["pack"].clone()).unwrap();
        let profile = tenzro_consensus::eu_ai_act::build_profile(&pack);
        assert_eq!(serde_json::to_value(&profile).unwrap(), fixture["profile"]);
        let report = verify_profile(&pack, &profile, &anchor, None).unwrap();
        assert_eq!(report.signed_tool_calls, 2);

        let mut p = pack.clone();
        p.audit[0].entry.body = String::from_utf8(p.audit[0].entry.body.clone())
            .unwrap()
            .replace("get_balance", "get_secrets")
            .into_bytes();
        assert!(verify_profile(&p, &profile, &anchor, None).is_err());
        let wrong = GenesisAnchor {
            chain_id: anchor.chain_id + 1,
            ..anchor
        };
        assert!(verify_profile(&pack, &profile, &wrong, None).is_err());
    }

    /// The shared receipt fixture, certified from genesis by a test committee
    /// (`tenzro-consensus` writes it): the whole check runs from the genesis
    /// anchor alone, and anything not certified from that anchor is refused.
    #[test]
    fn a_receipt_verifies_end_to_end_from_the_genesis_anchor() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/governance_receipt/receipt_from_genesis.json");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let anchor = GenesisAnchor {
            chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
            genesis_hash: hex32(
                fixture["anchor"]["genesis_hash"].as_str().unwrap(),
                "genesis hash",
            )
            .unwrap(),
            committee_root: hex32(
                fixture["anchor"]["committee_root"].as_str().unwrap(),
                "committee root",
            )
            .unwrap(),
        };
        let receipt: GovernanceReceipt =
            serde_json::from_value(fixture["receipt"].clone()).unwrap();
        let report = verify_governance_receipt(&receipt, &anchor, None).unwrap();
        assert_eq!(
            report.checkpoint,
            fixture["certified_checkpoint"].as_u64().unwrap()
        );
        assert_eq!(report.executed_height, fixture["executed_height"].as_u64());
        assert_eq!(report.tally.unwrap()["yes"], "3");

        assert!(
            verify_governance_receipt(
                &receipt,
                &GenesisAnchor {
                    committee_root: [0; 32],
                    ..anchor
                },
                None
            )
            .is_err()
        );
        assert!(
            verify_governance_receipt(
                &receipt,
                &GenesisAnchor {
                    chain_id: anchor.chain_id + 1,
                    ..anchor
                },
                None
            )
            .is_err()
        );
        let mut r = receipt.clone();
        r.state_root = hex::encode([9u8; 32]);
        assert!(
            verify_governance_receipt(&r, &anchor, None).is_err(),
            "a root the checkpoint does not commit"
        );
        let mut r = receipt.clone();
        let tally = r.records.iter_mut().find(|x| x.kind == "tally").unwrap();
        tally.value = Some(hex::encode(br#"{"yes":"4","no":"0","total_eligible":"4"}"#));
        assert!(
            verify_governance_receipt(&r, &anchor, None).is_err(),
            "a tally the root does not hold"
        );
    }
}
