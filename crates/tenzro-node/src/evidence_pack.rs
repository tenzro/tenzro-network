//! `tenzro_exportEvidencePack`: one export per agent, or per deployment (a
//! root identity and its agents), that checks offline against a certified
//! checkpoint. The caller brings the audit entries and session receipts its
//! recorder holds; the node checks each entry against the root committed on
//! chain and proves the state the pack cites. See
//! [`tenzro_types::evidence_pack`].

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::Value;
use tenzro_storage::KvStore;
use tenzro_storage::state_trie::StateTrie;
use tenzro_types::agent_audit::{ActionKind, AuditProof, SignedSessionReceipt, parse_digest};
use tenzro_types::evidence_pack::{
    EvidencePack, Jurisdiction, ModelProvenance, Oversight, ProvenRecord, STATE_NAMESPACE,
    vm_storage_key,
};
use tenzro_types::settlement::{PaymentRecord, payment_record_key};
use tenzro_vm::native::SYSTEM_ADDRESS;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Most audit entries one export carries.
pub(crate) const MAX_ENTRIES: usize = 2_000;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// The latest certified state: the trie, its height and root, and the
/// certification of the checkpoint certifying it (from genesis, or from the
/// handover chain proof on a node that pruned the handovers it covers).
pub(crate) struct Certified {
    pub storage: Arc<dyn KvStore>,
    pub trie: StateTrie,
    pub height: u64,
    pub state_root: String,
    pub state_trie_hash: tenzro_types::hash_scheme::HashScheme,
    pub checkpoint: Value,
}

pub(crate) fn certified(node: &Arc<TenzroNode>) -> Result<Certified, JsonRpcError> {
    let consensus = node
        .consensus()
        .ok_or_else(|| err(-32000, "this node follows no chain"))?;
    let cert = consensus
        .latest_certificate()
        .ok_or_else(|| err(-32004, "no certified checkpoint yet"))?;
    let cp = cert.checkpoint.clone();
    let checkpoint = node
        .certification(cp.index)
        .ok_or_else(|| err(-32004, "this node cannot certify the latest checkpoint"))?;
    let storage = node
        .storage()
        .ok_or_else(|| err(-32603, "storage not initialised"))?
        .clone() as Arc<dyn KvStore>;
    let trie = StateTrie::new(storage.clone());
    let state_trie_hash = trie
        .scheme_at(cp.state_height)
        .map_err(|e| err(-32603, format!("state trie: {e}")))?;
    Ok(Certified {
        trie,
        storage,
        height: cp.state_height,
        state_root: hex::encode(cp.state_root),
        state_trie_hash,
        checkpoint: serde_json::to_value(&checkpoint).map_err(|e| err(-32603, e.to_string()))?,
    })
}

/// `tenzro_getGovernanceReceipt { proposal_id }`: the proposal's records,
/// proven under the latest certified state, with that checkpoint's proof
/// from genesis. See [`tenzro_types::evidence_pack::GovernanceReceipt`].
pub(crate) fn handle_governance_receipt(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let id = params
        .as_ref()
        .and_then(|p| {
            p.get("proposal_id")
                .or_else(|| p.get(0).and_then(|o| o.get("proposal_id")))
        })
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .filter(|b| b.len() == 32)
        .map(hex::encode)
        .ok_or_else(|| err(-32602, "proposal_id is 32 bytes of hex"))?;
    let Certified {
        storage,
        trie,
        height,
        state_root,
        state_trie_hash,
        checkpoint,
    } = certified(node)?;
    let chain = tenzro_vm::StateAdapter::with_storage(storage);
    let records = tenzro_vm::native::governance_receipt_slots(&chain, &id)
        .into_iter()
        .map(|(kind, slot)| prove(&trie, height, kind, &id, slot))
        .collect::<Result<Vec<_>, _>>()?;
    if records.first().is_none_or(|r| r.value.is_none()) {
        return Err(err(
            -32004,
            format!("no proposal {id} is in the certified state at height {height}"),
        ));
    }
    let receipt = tenzro_types::evidence_pack::GovernanceReceipt {
        proposal_id: id,
        state_height: height,
        state_root,
        state_trie_hash,
        checkpoint,
        records,
    };
    serde_json::to_value(receipt).map_err(|e| err(-32603, e.to_string()))
}

/// Prove the system storage slot `slot` at `height`.
pub(crate) fn prove(
    trie: &StateTrie,
    height: u64,
    kind: &str,
    subject: &str,
    slot: String,
) -> Result<ProvenRecord, JsonRpcError> {
    let key = vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes());
    let (value, proof) = trie
        .prove(height, STATE_NAMESPACE, &key)
        .map_err(|e| err(-32603, format!("prove {slot}: {e}")))?;
    Ok(ProvenRecord {
        kind: kind.to_string(),
        subject: subject.to_string(),
        slot,
        value: value.map(hex::encode),
        proof: serde_json::to_value(proof).map_err(|e| err(-32603, e.to_string()))?,
    })
}

/// Most payment records one pack carries.
const MAX_PAYMENTS: usize = 256;
/// Most proposals or tokens one pack section names.
const MAX_SECTION_ITEMS: usize = 256;
/// Most issuer actions one pack carries per token, the latest.
const MAX_ACTIONS_PER_TOKEN: u64 = 256;

fn hex_list(params: &Value, key: &str, len: usize) -> Result<Vec<Vec<u8>>, JsonRpcError> {
    let items = params
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.len() > MAX_SECTION_ITEMS {
        return Err(err(
            -32602,
            format!("a pack names at most {MAX_SECTION_ITEMS} {key}"),
        ));
    }
    items
        .iter()
        .map(|v| {
            v.as_str()
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                .filter(|b| b.len() == len)
                .ok_or_else(|| err(-32602, format!("each of '{key}' is {len} bytes of hex")))
        })
        .collect()
}

/// Each named proposal's record and decision record, proven.
fn prove_governance(
    trie: &StateTrie,
    height: u64,
    chain: &dyn tenzro_vm::traits::VmState,
    params: &Value,
) -> Result<Vec<ProvenRecord>, JsonRpcError> {
    let mut out = Vec::new();
    for id in hex_list(params, "proposals", 32)? {
        let id = hex::encode(id);
        for (kind, slot) in tenzro_vm::native::governance_receipt_slots(chain, &id) {
            if matches!(kind, "proposal" | "decision") {
                out.push(prove(trie, height, kind, &id, slot)?);
            }
        }
    }
    Ok(out)
}

/// The latest issuer actions of each named token, proven, with the count
/// that numbers them.
fn prove_token_actions(
    trie: &StateTrie,
    height: u64,
    params: &Value,
) -> Result<Vec<ProvenRecord>, JsonRpcError> {
    use tenzro_vm::native::token::{issuer_action_count_slot, issuer_action_slot};
    let mut out = Vec::new();
    for id in hex_list(params, "tokens", 32)? {
        let id: [u8; 32] = id.try_into().expect("length checked");
        let subject = hex::encode(id);
        let counted = prove(
            trie,
            height,
            "token_action_count",
            &subject,
            issuer_action_count_slot(&id),
        )?;
        let count: u64 = counted
            .value
            .as_deref()
            .and_then(|v| hex::decode(v).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(0);
        out.push(counted);
        for seq in count.saturating_sub(MAX_ACTIONS_PER_TOKEN)..count {
            out.push(prove(
                trie,
                height,
                "token_action",
                &format!("{subject}:{seq}"),
                issuer_action_slot(&id, seq),
            )?);
        }
    }
    Ok(out)
}

/// `tenzro_exportEvidencePack { agent_did } | { root_did }`, optionally
/// `audit` (entry proofs from the agents' recorder), `receipts` (their
/// signed session receipts), `agents` (the root's agents to cover) and
/// `payments` (pay_refs of the covered agents' payments), `proposals`
/// (governance decisions touching the subject), `tokens` (tokens whose
/// issuer actions to prove).
pub(crate) async fn handle_export(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
    auth_ctx: &crate::rpc::AuthContext,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let agent = params
        .get("agent_did")
        .and_then(Value::as_str)
        .map(str::to_string);
    let root = params
        .get("root_did")
        .and_then(Value::as_str)
        .map(str::to_string);
    let (subject, covers): (String, Box<dyn Fn(&str) -> bool + Send>) = match (agent, root) {
        (Some(a), None) => (a.clone(), Box::new(move |d: &str| d == a)),
        (None, Some(r)) => (
            r.clone(),
            Box::new(move |d: &str| tenzro_vm::funding::root_did(d) == r),
        ),
        _ => return Err(err(-32602, "give exactly one of 'agent_did' or 'root_did'")),
    };
    let controller = tenzro_vm::funding::root_did(&subject);
    crate::agent_audit::may_read(node, auth_ctx, Some(&controller)).await?;
    let mut audit: Vec<AuditProof> = match params.get("audit") {
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| err(-32602, format!("audit: {e}")))?
        }
        None => Vec::new(),
    };
    let tool_calls = params
        .get("tool_calls")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if audit.len() > MAX_ENTRIES {
        return Err(err(
            -32602,
            format!("a pack carries at most {MAX_ENTRIES} audit entries"),
        ));
    }
    let receipts: Vec<SignedSessionReceipt> = match params.get("receipts") {
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| err(-32602, format!("receipts: {e}")))?
        }
        None => Vec::new(),
    };

    let Certified {
        storage,
        trie,
        height,
        state_root,
        state_trie_hash,
        checkpoint,
    } = certified(node)?;

    let mut agents: Vec<String> = Vec::new();
    let named = params
        .get("agents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for a in named.iter().filter_map(Value::as_str).map(str::to_string) {
        if !covers(&a) {
            return Err(err(-32602, format!("{a} is not an agent of {subject}")));
        }
        if !agents.contains(&a) {
            agents.push(a);
        }
    }
    if !subject.starts_with("did:tenzro:human:") && !agents.contains(&subject) {
        agents.push(subject.clone());
    }
    if tool_calls {
        let room = MAX_ENTRIES.saturating_sub(audit.len());
        let own = node
            .tool_calls()
            .proofs(&agents, room)
            .map_err(|e| err(-32603, e))?;
        audit.extend(own);
    }

    let chain = tenzro_vm::StateAdapter::with_storage(storage.clone());
    let mut commitments = Vec::new();
    let mut seen = BTreeSet::new();
    for p in &audit {
        let entry = p
            .entry
            .entry()
            .map_err(|e| err(-32602, format!("an audit entry does not decode: {e}")))?;
        if !covers(&entry.agent) {
            return Err(err(
                -32602,
                format!(
                    "an audit entry is of {}, which this pack does not cover",
                    entry.agent
                ),
            ));
        }
        if !agents.contains(&entry.agent) {
            agents.push(entry.agent.clone());
        }
        let committer = hex::decode(p.committer.trim_start_matches("0x"))
            .map_err(|_| err(-32602, "a proof names a malformed committer"))?;
        let root = p
            .verify()
            .map_err(|e| err(-32602, format!("an audit proof does not verify: {e}")))?;
        let committed = tenzro_vm::native::read_agent_audit(&chain, &committer, p.epoch)
            .ok_or_else(|| {
                err(
                    -32004,
                    format!(
                        "no root is committed for {} at epoch {}",
                        p.committer, p.epoch
                    ),
                )
            })?;
        if parse_digest(&committed.root).map_err(|e| err(-32603, e))? != root {
            return Err(err(
                -32602,
                format!(
                    "an audit entry reaches a root {} did not commit at epoch {}",
                    p.committer, p.epoch
                ),
            ));
        }
        if seen.insert((p.committer.clone(), p.epoch)) {
            commitments.push(prove(
                &trie,
                height,
                "audit_commit",
                &format!("{}:{}", p.committer, p.epoch),
                tenzro_vm::native::agent_audit::record_key(&committer, p.epoch),
            )?);
        }
    }

    let mut records = Vec::new();
    let mut mandate = Vec::new();
    let mut signers = BTreeSet::new();
    for p in &audit {
        if let Some(call) = p.entry.entry().ok().and_then(|e| e.call) {
            signers.insert(call.node);
        }
    }
    for did in &signers {
        mandate.push(prove(
            &trie,
            height,
            tenzro_consensus::eu_ai_act::NODE_IDENTITY_KIND,
            did,
            tenzro_types::identity::identity_slot(did),
        )?);
    }
    for a in &agents {
        mandate.push(prove(
            &trie,
            height,
            "terms",
            a,
            tenzro_vm::native::agent_terms::terms_key(a),
        )?);
        records.push(prove(
            &trie,
            height,
            "quarantine",
            a,
            tenzro_vm::native::agent_audit::quarantine_key(a),
        )?);
    }
    let mut commerce = Vec::new();
    let pay_refs = params
        .get("payments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if pay_refs.len() > MAX_PAYMENTS {
        return Err(err(
            -32602,
            format!("a pack carries at most {MAX_PAYMENTS} payments"),
        ));
    }
    for r in pay_refs {
        let pay_ref: [u8; 32] = r
            .as_str()
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| err(-32602, "each payment is a 32-byte hex pay_ref"))?;
        let subject_ref = hex::encode(pay_ref);
        let proven = prove(
            &trie,
            height,
            "payment",
            &subject_ref,
            payment_record_key(&pay_ref),
        )?;
        let record: PaymentRecord = proven
            .value
            .as_deref()
            .and_then(|v| hex::decode(v).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| {
                err(
                    -32004,
                    format!("no payment is recorded at {subject_ref} at height {height}"),
                )
            })?;
        if !record
            .agent_did
            .as_deref()
            .is_some_and(|d| agents.iter().any(|a| a == d))
        {
            return Err(err(
                -32602,
                format!("payment {subject_ref} was not made by an agent this pack covers"),
            ));
        }
        commerce.push(proven);
    }
    let governance = prove_governance(&trie, height, &chain, &params)?;
    let token_actions = prove_token_actions(&trie, height, &params)?;
    let mut actions = Vec::new();
    let mut models = BTreeSet::new();
    for p in &audit {
        let Ok(entry) = p.entry.entry() else { continue };
        match entry.kind {
            ActionKind::GrantUse | ActionKind::Approval => {
                actions.push((hex::encode(entry.session_id), entry.seq));
            }
            ActionKind::ModelCall => {
                models.insert(entry.action.clone());
            }
            _ => {}
        }
    }
    let models = models
        .into_iter()
        .map(|model| ModelProvenance {
            files: tenzro_model::catalog::entry(&model)
                .map(|e| {
                    e.components
                        .iter()
                        .map(|c| (c.path.clone(), c.sha256.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            model,
        })
        .collect();

    let mut pack = EvidencePack {
        subject,
        agents,
        generated_at_ms: tenzro_crypto::session::now_ms(),
        state_height: height,
        state_root,
        state_trie_hash,
        checkpoint,
        audit,
        commitments,
        oversight: Oversight { records, actions },
        mandate,
        commerce,
        governance,
        token_actions,
        receipts,
        models,
        jurisdiction: Jurisdiction {
            country: node.config().jurisdiction_country.clone(),
            blocs: node.config().jurisdiction_blocs.clone(),
        },
        manifest: Vec::new(),
    };
    pack.manifest = pack.build_manifest();
    serde_json::to_value(pack).map_err(|e| err(-32603, e.to_string()))
}
