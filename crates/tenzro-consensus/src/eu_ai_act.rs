//! The EU AI Act profile of an evidence pack, and the offline check of the
//! tool-call records serving nodes sign for agents.
//!
//! A profile maps what a pack proves to the record-keeping and human
//! oversight provisions of Regulation (EU) 2024/1689: Art. 12 (automatic
//! recording of events) and Art. 14 (approval, revocation and halt). Each
//! clause lists the pack items it rests on, what they establish and what
//! they do not. It is built from the pack alone ([`build_profile`]), so a
//! verifier rebuilds it and refuses a profile that claims anything more
//! ([`verify_profile`]).
//!
//! Nothing here is a legal assessment: a profile states which records exist
//! and verify, not whether a system complies.
//!
//! A tool-call entry a serving node recorded ([`ToolCallFacts`]) is checked
//! against the identity that node registered on chain: the pack proves the
//! registration under its certified state root (a `node_identity` record in
//! `mandate`), and the entry's batch signature must verify under that key
//! at the time the entry states.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::CompositePublicKey;
use tenzro_crypto::batch::RecordSignature;
use tenzro_types::agent_audit::{ActionKind, ActionOutcome, AuditEntry, SignedAuditEntry};
use tenzro_types::evidence_pack::{EvidencePack, ProvenRecord};

use crate::evidence_pack::{VerifyReport, check_record, verify_pack_with, verify_under_root};
use crate::light_client::GenesisAnchor;

/// Name of the profile this module builds.
pub const EU_AI_ACT_PROFILE: &str = "eu-ai-act/2024-1689/v1";

/// Kind of the `mandate` record that proves a serving node's registered
/// identity.
pub const NODE_IDENTITY_KIND: &str = "node_identity";

/// The fields of an identity registration record that name its key.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisteredKeyFields {
    pub did: String,
    pub controller_pubkey: Vec<u8>,
    pub key_type: String,
    #[serde(default)]
    pub pq_verifying_key: Vec<u8>,
}

/// The hardware identity key `did` registered: its P-256 point and, when
/// enrolled, its ML-DSA-65 key. Only hardware P-256 keys sign records.
pub fn registered_key(
    did: &str,
    controller_pubkey: &[u8],
    key_type: &str,
    pq_verifying_key: &[u8],
) -> Result<CompositePublicKey, String> {
    if !matches!(key_type.to_ascii_lowercase().as_str(), "p256" | "p-256") {
        return Err(format!(
            "{did}'s key type {key_type} is not a hardware P-256 key"
        ));
    }
    let p256 = match controller_pubkey {
        [0x04, xy @ ..] if xy.len() == 64 => xy.to_vec(),
        xy => xy.to_vec(),
    };
    let pq = (!pq_verifying_key.is_empty()).then(|| pq_verifying_key.to_vec());
    CompositePublicKey::new(p256, pq).map_err(|_| format!("{did}'s key is not a P-256 point"))
}

/// Check that `key` signed `entry` when it says it was recorded, and return
/// the entry.
pub fn verify_tool_call(
    entry: &SignedAuditEntry,
    key: &CompositePublicKey,
) -> Result<AuditEntry, String> {
    let e = entry.entry()?;
    let signature: RecordSignature = serde_json::from_slice(&entry.signature).map_err(|_| {
        format!(
            "entry {} of {}: the signature does not decode",
            e.seq, e.agent
        )
    })?;
    signature
        .verify_record_at(key, &entry.body, e.at_ms)
        .map_err(|err| format!("entry {} of {}: {err}", e.seq, e.agent))?;
    Ok(e)
}

/// The registered keys of the serving nodes the pack proves, by DID.
fn node_keys(
    pack: &EvidencePack,
    root: &[u8; 32],
) -> Result<HashMap<String, CompositePublicKey>, String> {
    let mut keys = HashMap::new();
    for r in pack.mandate.iter().filter(|r| r.kind == NODE_IDENTITY_KIND) {
        if r.slot != tenzro_types::identity::identity_slot(&r.subject) {
            return Err(format!(
                "the identity of {} is proven at another slot",
                r.subject
            ));
        }
        let value = check_record(pack.state_trie_hash, root, r)?
            .ok_or_else(|| format!("{} has no identity on chain", r.subject))?;
        let record: RegisteredKeyFields =
            serde_json::from_slice(&value).map_err(|e| format!("{}: {e}", r.subject))?;
        if record.did != r.subject {
            return Err(format!(
                "the identity proven for {} is {}",
                r.subject, record.did
            ));
        }
        keys.insert(
            r.subject.clone(),
            registered_key(
                &record.did,
                &record.controller_pubkey,
                &record.key_type,
                &record.pq_verifying_key,
            )?,
        );
    }
    Ok(keys)
}

/// Every node-recorded tool-call entry of the pack is signed by the serving
/// node's registered identity, proven under `root`. Returns how many were
/// checked.
pub fn verify_tool_calls_under_root(pack: &EvidencePack, root: &[u8; 32]) -> Result<usize, String> {
    let keys = node_keys(pack, root)?;
    let mut checked = 0;
    for p in &pack.audit {
        let e = p.entry.entry()?;
        let Some(call) = &e.call else { continue };
        let key = keys.get(&call.node).ok_or_else(|| {
            format!(
                "entry {} of {} is signed by {}, whose identity the pack does not prove",
                e.seq, e.agent, call.node
            )
        })?;
        verify_tool_call(&p.entry, key)?;
        checked += 1;
    }
    Ok(checked)
}

/// One provision of the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clause {
    /// Control reference, as the pack's manifest names it.
    pub id: String,
    /// What the provision asks for, in short.
    pub requirement: String,
    /// The oversight measure, for Art. 14: `approval`, `revocation`, `halt`
    /// or `mandate`; `recording` or `monitoring` for Art. 12.
    pub measure: String,
    /// The pack items it rests on: `audit:<session>:<seq>`,
    /// `commitment:<committer>:<epoch>`, `<kind>:<subject>` for a chain
    /// record, `model:<id>`, `receipt:<n>`.
    pub evidence: Vec<String>,
    /// What those items establish once the pack verifies.
    pub proves: String,
    /// What they do not establish.
    pub does_not_prove: String,
}

/// The profile of one pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub profile: String,
    pub subject: String,
    pub state_height: u64,
    pub state_root: String,
    /// SHA-256 of the pack's manifest JSON, binding the profile to the pack.
    pub manifest_digest: String,
    pub clauses: Vec<Clause>,
}

fn entry_ref(e: &AuditEntry) -> String {
    format!("audit:{}:{}", hex::encode(e.session_id), e.seq)
}

fn record_ref(r: &ProvenRecord) -> String {
    match r.value {
        Some(_) => format!("{}:{}", r.kind, r.subject),
        None => format!("{}-absent:{}", r.kind, r.subject),
    }
}

fn quarantine_revoked(r: &ProvenRecord) -> Option<bool> {
    let bytes = hex::decode(r.value.as_deref()?).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(v.get("revoked").and_then(|b| b.as_bool()).unwrap_or(false))
}

fn clause(
    id: &str,
    measure: &str,
    requirement: &str,
    evidence: Vec<String>,
    proves: &str,
    not: &str,
) -> Clause {
    Clause {
        id: id.into(),
        requirement: requirement.into(),
        measure: measure.into(),
        evidence,
        proves: proves.into(),
        does_not_prove: not.into(),
    }
}

/// The profile of `pack`, from its contents alone.
pub fn build_profile(pack: &EvidencePack) -> Profile {
    let entries: Vec<AuditEntry> = pack
        .audit
        .iter()
        .filter_map(|p| p.entry.entry().ok())
        .collect();

    let mut recording: Vec<String> = entries.iter().map(entry_ref).collect();
    recording.extend(
        pack.commitments
            .iter()
            .map(|r| format!("commitment:{}", r.subject)),
    );

    let mut monitoring: Vec<String> = entries
        .iter()
        .filter(|e| {
            matches!(e.outcome, ActionOutcome::Refused(_)) || e.kind == ActionKind::Violation
        })
        .map(entry_ref)
        .collect();
    monitoring.extend(pack.commerce.iter().map(record_ref));
    monitoring.extend(pack.token_actions.iter().map(record_ref));
    monitoring.extend((0..pack.receipts.len()).map(|i| format!("receipt:{i}")));
    monitoring.extend(pack.models.iter().map(|m| format!("model:{}", m.model)));

    let mut mandate: Vec<String> = pack.mandate.iter().map(record_ref).collect();
    let principals: BTreeSet<String> = entries
        .iter()
        .filter_map(|e| e.call.as_ref()?.principal.as_ref())
        .map(|p| format!("terms-approval:{}:{}", p.controller_did, p.approval_digest))
        .collect();
    mandate.extend(principals);

    let actions: BTreeSet<(String, u64)> = pack.oversight.actions.iter().cloned().collect();
    let approval: Vec<String> = entries
        .iter()
        .filter(|e| {
            e.kind == ActionKind::Approval
                || e.kind == ActionKind::GrantUse
                || matches!(e.outcome, ActionOutcome::Pending(_))
                || e.call.as_ref().is_some_and(|c| c.approval.is_some())
                || actions.contains(&(hex::encode(e.session_id), e.seq))
        })
        .map(entry_ref)
        .collect();

    let quarantines: Vec<&ProvenRecord> = pack
        .oversight
        .records
        .iter()
        .filter(|r| r.kind == "quarantine")
        .collect();
    let revocation: Vec<String> = quarantines
        .iter()
        .filter(|r| quarantine_revoked(r) != Some(false))
        .map(|r| record_ref(r))
        .collect();
    let mut halt: Vec<String> = quarantines
        .iter()
        .filter(|r| quarantine_revoked(r) != Some(true))
        .map(|r| record_ref(r))
        .collect();
    halt.extend(
        pack.oversight
            .records
            .iter()
            .filter(|r| r.kind != "quarantine")
            .map(record_ref),
    );
    halt.extend(pack.governance.iter().map(record_ref));

    let unaudited = "That the record is complete: actions an agent took through nodes or \
        recorders the pack does not cover, or that a node did not record, do not appear. \
        Nothing about whether the system is high-risk, or about its conformity.";
    Profile {
        profile: EU_AI_ACT_PROFILE.into(),
        subject: pack.subject.clone(),
        state_height: pack.state_height,
        state_root: pack.state_root.clone(),
        manifest_digest: hex::encode(Sha256::digest(
            serde_json::to_vec(&pack.manifest).unwrap_or_default(),
        )),
        clauses: vec![
            clause(
                "eu-ai-act:12(1)",
                "recording",
                "Automatic recording of events over the lifetime of the system.",
                recording,
                "Each listed entry was recorded and is fixed by the root its node committed on \
                 chain for the epoch named; entries of a session chain in order with no gap. A \
                 tool-call entry a serving node recorded is signed by that node's registered \
                 hardware identity, at the time it states, and names the tool and the digests of \
                 the arguments and the result.",
                unaudited,
            ),
            clause(
                "eu-ai-act:12(2)",
                "monitoring",
                "Records that identify situations that may present a risk, support post-market \
                 monitoring and monitor operation.",
                monitoring,
                "Refused calls with the reason given, payments the covered agents made, issuer \
                 actions on tokens they held, signed session receipts and the catalog hashes of \
                 the models they called, each as recorded or proven under the certified state.",
                "Whether any situation was in fact a risk, or that monitoring took place. The \
                 arguments and results themselves: only their digests are recorded.",
            ),
            clause(
                "eu-ai-act:14(3)",
                "mandate",
                "Oversight measures identified and built in before the system is put into use.",
                mandate,
                "The Terms each agent acted under, as chain state held them at the certified \
                 height; the identities of the serving nodes; for a delegated agent, the root \
                 that approved its Terms and the digest of that approval.",
                "That the Terms were adequate for the use, or that the person approving them \
                 understood them.",
            ),
            clause(
                "eu-ai-act:14(4)(d)",
                "approval",
                "The ability to decide not to use the output, or to override or reverse it: \
                 actions held for, or carried out under, a person's approval.",
                approval,
                "These actions were recorded as approval or grant actions, as held for an \
                 approval, or with an approval reference presented by the caller.",
                "That a presented approval reference was valid or that a person reviewed the \
                 action: the record states the reference as presented.",
            ),
            clause(
                "eu-ai-act:14(4)(d)",
                "revocation",
                "The ability to stop relying on an agent: revocation by its root.",
                revocation,
                "Whether each covered agent was revoked at the certified height: a revocation \
                 record, or a proven absence of any quarantine or revocation.",
                "What happened between revocation and the certified height on nodes that had \
                 not yet seen it; anything after the certified height.",
            ),
            clause(
                "eu-ai-act:14(4)(e)",
                "halt",
                "The ability to intervene or interrupt through a stop procedure.",
                halt,
                "Quarantines in force or proven absent at the certified height, and the \
                 governance decisions touching the subject, proven under the certified state.",
                "That a halt took effect on every node at the moment it was decided; anything \
                 after the certified height.",
            ),
        ],
    }
}

/// What a verified profile established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileReport {
    pub pack: VerifyReport,
    /// Tool-call entries whose node signature verified.
    pub signed_tool_calls: usize,
}

/// `pack` verifies under `root`, its tool-call entries carry their nodes'
/// signatures, and `profile` is exactly the pack's profile.
pub fn verify_profile_under_root(
    pack: &EvidencePack,
    profile: &Profile,
    root: &[u8; 32],
) -> Result<(usize, usize, usize), String> {
    let (entries, records) = verify_under_root(pack, root)?;
    let signed = verify_tool_calls_under_root(pack, root)?;
    if *profile != build_profile(pack) {
        return Err("the profile does not match the pack it names".into());
    }
    Ok((entries, records, signed))
}

/// [`verify_profile_under_root`] for the state root the pack's checkpoint
/// certifies from `anchor` (or from a handover chain proof of
/// `handover_program`, checked with `verify_receipt`).
pub fn verify_profile<F>(
    pack: &EvidencePack,
    profile: &Profile,
    anchor: &GenesisAnchor,
    handover_program: Option<[u8; 32]>,
    verify_receipt: F,
) -> Result<ProfileReport, String>
where
    F: FnOnce(&[u8; 32], &[u8]) -> Result<Vec<u8>, String>,
{
    let report = verify_pack_with(pack, anchor, handover_program, verify_receipt)?;
    let root: [u8; 32] = hex::decode(&pack.state_root)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the pack's state root is not 32 bytes of hex")?;
    let signed = verify_tool_calls_under_root(pack, &root)?;
    if *profile != build_profile(pack) {
        return Err("the profile does not match the pack it names".into());
    }
    Ok(ProfileReport {
        pack: report,
        signed_tool_calls: signed,
    })
}

/// A pack whose entries reach a root chain state records for the
/// committer: two tool calls a serving node recorded and signed, one entry
/// of an outside recorder, the node's registered identity, the agent's
/// Terms and its revocation, all proven under a real state root.
#[cfg(test)]
pub(crate) mod fixture {
    use std::sync::Arc;

    use tenzro_crypto::batch::{ImmediateRecordSigner, RecordSigner};
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::agent_audit::{
        ActionKind, ActionOutcome, AuditEntry, AuditProof, CallPrincipal, Mmr, SessionLeaf,
        SignedAuditEntry, ToolCallFacts, detail_digest, epoch_root, prove_epoch,
    };
    use tenzro_types::evidence_pack::{
        EvidencePack, Jurisdiction, Oversight, ProvenRecord, STATE_NAMESPACE, vm_storage_key,
    };

    const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];
    pub const AGENT: &str = "did:tenzro:human:alice:bot";
    pub const SESSION: [u8; 32] = [5; 32];

    pub fn node_signer() -> ImmediateRecordSigner {
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(21));
        ImmediateRecordSigner::new(id)
    }

    pub fn node_did(s: &ImmediateRecordSigner) -> String {
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&s.identity().p256);
        tenzro_types::did_derivation::machine_did(&sec1)
    }

    pub fn tool_call(
        s: &ImmediateRecordSigner,
        seq: u64,
        prev: [u8; 32],
        tool: &str,
        outcome: ActionOutcome,
        approval: Option<&str>,
    ) -> SignedAuditEntry {
        let refused = matches!(outcome, ActionOutcome::Refused(_));
        let e = AuditEntry {
            session_id: SESSION,
            seq,
            at_ms: tenzro_crypto::session::now_ms(),
            agent: AGENT.into(),
            kind: ActionKind::ToolCall,
            action: tool.into(),
            outcome,
            detail: detail_digest(format!("args-{seq}").as_bytes()),
            linked_tx: None,
            prev,
            image: None,
            call: Some(ToolCallFacts {
                node: node_did(s),
                surface: "mcp".into(),
                principal: Some(CallPrincipal {
                    controller_did: "did:tenzro:human:alice".into(),
                    root_kind: "passkey".into(),
                    terms_version: 2,
                    approval_digest: "cd".repeat(32),
                }),
                result: (!refused).then(|| hex::encode(detail_digest(b"result"))),
                approval: approval.map(str::to_string),
            }),
        };
        let body = serde_json::to_vec(&e).unwrap();
        let sig = s.sign_record(&body).unwrap();
        SignedAuditEntry {
            body,
            signature: serde_json::to_vec(&sig).unwrap(),
        }
    }

    /// The pack, before a checkpoint is attached, and its state root.
    pub fn pack() -> (EvidencePack, [u8; 32]) {
        let s = node_signer();
        let did = node_did(&s);
        let first = tool_call(
            &s,
            0,
            [0; 32],
            "get_balance",
            ActionOutcome::Allowed,
            Some("ticket-41"),
        );
        let second = tool_call(
            &s,
            1,
            first.leaf_hash(),
            "send_transaction",
            ActionOutcome::Refused("outside the agent's terms".into()),
            None,
        );
        let outside = {
            let e = AuditEntry {
                session_id: SESSION,
                seq: 2,
                at_ms: 1,
                agent: AGENT.into(),
                kind: ActionKind::Approval,
                action: "checkout".into(),
                outcome: ActionOutcome::Pending("approval-9".into()),
                detail: [2; 32],
                linked_tx: None,
                prev: second.leaf_hash(),
                image: None,
                call: None,
            };
            SignedAuditEntry {
                body: serde_json::to_vec(&e).unwrap(),
                signature: vec![],
            }
        };
        let entries = [first, second, outside];
        let mmr = Mmr::from_leaves(entries.iter().map(|e| e.leaf_hash()));
        let leaves = vec![SessionLeaf {
            session_id: SESSION,
            mmr_root: mmr.root(),
            count: 3,
        }];
        let audit: Vec<AuditProof> = entries
            .into_iter()
            .enumerate()
            .map(|(i, e)| AuditProof {
                entry: e,
                mmr: mmr.prove(i as u64, 3).unwrap(),
                epoch_proof: prove_epoch(&leaves, &SESSION).unwrap(),
                epoch: 4,
                committer: "0xaa".into(),
            })
            .collect();

        let mut key = vec![0x04];
        key.extend_from_slice(&s.identity().p256);
        let identity_slot = tenzro_types::identity::identity_slot(&did);
        let slots = [
            (
                "agent_audit:aa:0000000000000004".to_string(),
                serde_json::json!({ "root": hex::encode(epoch_root(&leaves)), "sessions": 1 }),
            ),
            (
                format!("agent_terms:{AGENT}"),
                serde_json::json!({ "version": 2 }),
            ),
            (
                identity_slot.clone(),
                serde_json::json!({
                    "did": did, "identity_type": "machine", "display_name": "node",
                    "controller_pubkey": key, "key_type": "p256",
                }),
            ),
            (
                format!("agent_quarantine:{AGENT}"),
                serde_json::json!({ "controller_did": "did:tenzro:human:alice", "revoked": true }),
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
        let state_root = trie.commit(1, &writes).unwrap();
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
        let mut pack = EvidencePack {
            subject: AGENT.into(),
            agents: vec![AGENT.into()],
            generated_at_ms: 0,
            state_height: 1,
            state_root: hex::encode(state_root.as_bytes()),
            state_trie_hash: trie.scheme_at(1).unwrap(),
            checkpoint: serde_json::Value::Null,
            audit,
            commitments: vec![record("audit_commit", "0xaa:4", &slots[0].0)],
            oversight: Oversight {
                records: vec![record("quarantine", AGENT, &slots[3].0)],
                actions: vec![(hex::encode(SESSION), 2)],
            },
            mandate: vec![
                record("terms", AGENT, &slots[1].0),
                record(super::NODE_IDENTITY_KIND, &did, &identity_slot),
            ],
            commerce: vec![],
            governance: vec![],
            token_actions: vec![],
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause<'a>(p: &'a Profile, measure: &str) -> &'a Clause {
        p.clauses.iter().find(|c| c.measure == measure).unwrap()
    }

    #[test]
    fn a_profile_maps_the_pack_and_verifies_under_its_root() {
        let (pack, root) = fixture::pack();
        let profile = build_profile(&pack);
        assert_eq!(
            verify_profile_under_root(&pack, &profile, &root).unwrap(),
            (3, 4, 2)
        );
        let session = hex::encode(fixture::SESSION);
        assert_eq!(clause(&profile, "recording").evidence.len(), 4);
        assert_eq!(
            clause(&profile, "monitoring").evidence,
            vec![format!("audit:{session}:1")]
        );
        assert_eq!(
            clause(&profile, "approval").evidence,
            vec![format!("audit:{session}:0"), format!("audit:{session}:2")]
        );
        assert_eq!(
            clause(&profile, "revocation").evidence,
            vec![format!("quarantine:{}", fixture::AGENT)]
        );
        assert!(clause(&profile, "halt").evidence.is_empty());
        assert!(
            clause(&profile, "mandate")
                .evidence
                .iter()
                .any(|e| e.starts_with("terms-approval:did:tenzro:human:alice:"))
        );
        for c in &profile.clauses {
            assert!(c.id.starts_with("eu-ai-act:1"));
            assert!(!c.proves.is_empty() && !c.does_not_prove.is_empty());
        }
    }

    /// The pack verifier alone checks only that an entry reaches the
    /// committed root; a forged node signature passes it. The profile check
    /// refuses it, and every other tampering.
    #[test]
    fn a_forged_or_unproven_node_signature_is_refused() {
        let (pack, root) = fixture::pack();
        let profile = build_profile(&pack);
        let other = {
            let id: std::sync::Arc<dyn tenzro_crypto::composite::HybridSigner> =
                std::sync::Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(22));
            tenzro_crypto::batch::ImmediateRecordSigner::new(id)
        };
        let mut forged = pack.clone();
        let sig =
            tenzro_crypto::batch::RecordSigner::sign_record(&other, &forged.audit[0].entry.body)
                .unwrap();
        forged.audit[0].entry.signature = serde_json::to_vec(&sig).unwrap();
        // Re-commit is out of reach of a forger, so the forged entry no longer
        // reaches the root either; check the signature alone, as a verifier
        // given the entry would.
        assert!(verify_tool_calls_under_root(&forged, &root).is_err());

        // The node's identity must be proven by the pack.
        let mut p = pack.clone();
        p.mandate.retain(|r| r.kind != NODE_IDENTITY_KIND);
        p.manifest = p.build_manifest();
        assert!(verify_under_root(&p, &root).is_ok());
        assert!(verify_profile_under_root(&p, &build_profile(&p), &root).is_err());

        // An identity proven at another DID's slot does not stand for it.
        let mut p = pack.clone();
        let r = p
            .mandate
            .iter_mut()
            .find(|r| r.kind == NODE_IDENTITY_KIND)
            .unwrap();
        r.subject = "did:tenzro:machine:other".into();
        p.manifest = p.build_manifest();
        assert!(verify_profile_under_root(&p, &build_profile(&p), &root).is_err());

        // A profile that claims more than the pack holds is refused.
        let mut claimed = profile.clone();
        claimed.clauses[4]
            .evidence
            .push("quarantine:did:tenzro:human:alice:other".into());
        assert!(verify_profile_under_root(&pack, &claimed, &root).is_err());
        let mut claimed = profile.clone();
        claimed.clauses[0]
            .proves
            .push_str(" And that the system complies.");
        assert!(verify_profile_under_root(&pack, &claimed, &root).is_err());

        // A body changed after signing fails its signature.
        let key = {
            let s = fixture::node_signer();
            s.identity().clone()
        };
        let mut e = pack.audit[0].entry.clone();
        e.body = String::from_utf8(e.body)
            .unwrap()
            .replace("get_balance", "get_secrets")
            .into_bytes();
        assert!(verify_tool_call(&e, &key).is_err());
        assert!(verify_tool_call(&pack.audit[0].entry, &key).is_ok());
    }

    #[test]
    fn a_batch_signed_tool_call_verifies_and_a_changed_one_does_not() {
        use tenzro_crypto::batch::{BatchParams, BatchService, RecordSignature};
        use tenzro_crypto::testing::TestHybridSigner;
        let svc = BatchService::new(
            std::sync::Arc::new(TestHybridSigner::hybrid(22)),
            BatchParams {
                max_batch: 8,
                flush_interval_ms: 1_000,
            },
            0,
        )
        .unwrap();
        let mut entry = super::fixture::tool_call(
            &super::fixture::node_signer(),
            0,
            [0; 32],
            "search",
            tenzro_types::agent_audit::ActionOutcome::Allowed,
            None,
        );
        let batched = svc
            .sign_now(entry.body.clone(), tenzro_crypto::session::now_ms())
            .map(RecordSignature::batched)
            .unwrap();
        entry.signature = serde_json::to_vec(&batched).unwrap();
        let key = svc.identity().clone();
        assert!(verify_tool_call(&entry, &key).is_ok());
        let mut changed = entry.clone();
        let n = changed.body.len();
        changed.body[n - 3] ^= 1;
        assert!(verify_tool_call(&changed, &key).is_err());
    }
}
