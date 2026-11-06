//! Guardrails a delegated agent's configuration must satisfy, decided by the
//! node outside the agent.
//!
//! An agent that can read private data, takes in content from outside its
//! terms, and can send data off the network is one injected instruction away
//! from leaking that data. The node derives those three exposures from the
//! agent's terms on chain and the machine-access grants made out to it, and
//! refuses the combination unless the controller's approved terms carry
//! `trifecta_exception`. The VM refuses such terms on its own; the node adds
//! the grants, which only it holds.
//!
//! What a delegated agent asks the node to do is a typed proposal, never a
//! free-form call: an operation, and the model or counterparty it names,
//! which [`tenzro_types::agent_terms::check_scope`] validates against the
//! terms before anything runs. A keyed request is a proposal by its method
//! ([`keyed_proposal`]); a bearer request carries a typed intent
//! ([`check_bearer_intent`]). Value moves only through `tenzro_agentAct`,
//! whose action the VM checks again. A request that maps to no proposal is
//! refused.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_identity::DelegationEntry;
use tenzro_types::agent_terms::{AgentAction, Exposure, check_scope, check_trifecta};

use crate::node::TenzroNode;

/// RPC methods that run a model: the `inference` operation.
pub(crate) const MODEL_METHODS: &[&str] = &[
    "tenzro_chat",
    "tenzro_inference",
    "tenzro_generate",
    "tenzro_textEmbed",
    "tenzro_chatByIntent",
];

/// What a delegated agent's keyed request proposes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Proposal {
    /// `tenzro_agentAct`, whose action is checked in full before it is
    /// signed and again by the VM, or `tenzro_agentVoucher`, whose voucher
    /// is checked against the ledger before it is signed and again by the
    /// VM at the claim.
    Act,
    /// A tool or skill invocation, checked by what it runs once it is
    /// resolved.
    Invocation,
    /// A read of state any caller may read.
    Read,
    /// An operation the scope check validates now.
    Operation {
        operation: &'static str,
        model: Option<String>,
    },
}

/// Whether `method` only reads.
fn is_read(method: &str) -> bool {
    let name = method.split_once('_').map_or(method, |(_, n)| n);
    name.starts_with("get")
        || name.starts_with("list")
        || name.starts_with("estimate")
        || matches!(
            name,
            "call" | "blockNumber" | "chainId" | "gasPrice" | "version" | "clientVersion"
        )
}

/// The typed proposal a delegated agent's keyed request to `method` makes,
/// or why it makes none.
pub(crate) fn keyed_proposal(method: &str, params: Option<&Value>) -> Result<Proposal, String> {
    if matches!(method, "tenzro_agentAct" | "tenzro_agentVoucher") {
        return Ok(Proposal::Act);
    }
    if matches!(method, "tenzro_useTool" | "tenzro_useSkill") {
        return Ok(Proposal::Invocation);
    }
    if MODEL_METHODS.contains(&method) {
        let p = params.map(|p| crate::rpc::unwrap_param_object(Some(p.clone())));
        let model = p
            .as_ref()
            .and_then(|p| p.get("model").or_else(|| p.get("model_id")))
            .and_then(Value::as_str)
            .map(str::to_string);
        return Ok(Proposal::Operation {
            operation: "inference",
            model,
        });
    }
    if is_read(method) {
        return Ok(Proposal::Read);
    }
    Err(format!(
        "a delegated agent acts only through typed actions; {method} is not one \
         (value moves through tenzro_agentAct)"
    ))
}

/// A proposal to perform `operation`, for the scope check.
fn proposal(did: &str, operation: &str, model: Option<String>) -> AgentAction {
    AgentAction {
        asset: None,
        usd_e6: 0,
        payment: None,
        agent_did: did.to_string(),
        machine_did: String::new(),
        operation: operation.to_string(),
        counterparty: String::new(),
        amount: 0,
        chain: String::new(),
        payment_protocol: None,
        model,
        calls: Vec::new(),
        escrow: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
        nonce: 0,
        tainted: false,
        step_up: None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// How long after the last untrusted input reached an agent its actions
/// count as deriving from it.
pub(crate) const TAINT_HOLD_MS: u64 = 3_600_000;

/// Where untrusted input last reached an agent on this node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct TaintLabel {
    /// What brought it in: an operation, or the sender of a message.
    pub source: String,
    /// When it last arrived, unix ms.
    pub at_ms: u64,
}

/// Key prefix of a label in the node's metadata column family.
const TAINT_KEY_PREFIX: &str = "agent_taint:";

/// The labels held on this node's agents. Once bound to the node's store
/// ([`TaintBook::attach`]) each label is also written there, so a label still
/// inside its hold window survives a restart.
#[derive(Default)]
pub(crate) struct TaintBook {
    labels: parking_lot::Mutex<std::collections::HashMap<String, TaintLabel>>,
    store: parking_lot::Mutex<Option<Arc<dyn tenzro_storage::KvStore>>>,
}

impl TaintBook {
    /// Binds the book to `store`: loads the labels it holds that are still
    /// inside the hold window at `now_ms`, deletes the ones that are not, and
    /// writes every later label through. A label already in memory that is
    /// newer than the stored one for its agent stands.
    pub(crate) fn attach(&self, store: Arc<dyn tenzro_storage::KvStore>, now_ms: u64) {
        let stored = store
            .scan_prefix(tenzro_storage::CF_METADATA, TAINT_KEY_PREFIX.as_bytes())
            .unwrap_or_else(|e| {
                tracing::warn!(target: "agent_guardrails", error = %e, "stored taint labels could not be read");
                Vec::new()
            });
        let mut labels = self.labels.lock();
        for (key, value) in stored {
            let held = std::str::from_utf8(&key)
                .ok()
                .and_then(|k| k.strip_prefix(TAINT_KEY_PREFIX))
                .zip(serde_json::from_slice::<TaintLabel>(&value).ok())
                .filter(|(_, l)| now_ms.saturating_sub(l.at_ms) < TAINT_HOLD_MS);
            match held {
                Some((did, stored_label)) => {
                    let newer = labels.get(did).is_some_and(|l| l.at_ms >= stored_label.at_ms);
                    if !newer {
                        labels.insert(did.to_string(), stored_label);
                    }
                }
                None => {
                    let _ = store.delete(tenzro_storage::CF_METADATA, &key);
                }
            }
        }
        // Labels set before the store was bound.
        for (did, l) in labels.iter() {
            Self::write(store.as_ref(), did, l);
        }
        drop(labels);
        *self.store.lock() = Some(store);
    }

    fn write(store: &dyn tenzro_storage::KvStore, did: &str, label: &TaintLabel) {
        let key = format!("{TAINT_KEY_PREFIX}{did}");
        match serde_json::to_vec(label) {
            Ok(bytes) => {
                if let Err(e) = store.put(tenzro_storage::CF_METADATA, key.as_bytes(), &bytes) {
                    tracing::warn!(target: "agent_guardrails", agent = %did, error = %e, "taint label not stored");
                }
            }
            Err(e) => {
                tracing::warn!(target: "agent_guardrails", agent = %did, error = %e, "taint label not encoded");
            }
        }
    }

    fn set(&self, did: &str, source: String, at_ms: u64) {
        let label = TaintLabel { source, at_ms };
        self.labels.lock().insert(did.to_string(), label.clone());
        if let Some(store) = self.store.lock().as_ref() {
            Self::write(store.as_ref(), did, &label);
        }
    }

    fn get(&self, did: &str, now_ms: u64) -> Option<TaintLabel> {
        self.labels
            .lock()
            .get(did)
            .filter(|l| now_ms.saturating_sub(l.at_ms) < TAINT_HOLD_MS)
            .cloned()
    }
}

fn taint() -> &'static TaintBook {
    static LABELS: std::sync::OnceLock<TaintBook> = std::sync::OnceLock::new();
    LABELS.get_or_init(Default::default)
}

/// Keeps the taint labels in `store` from now on and takes back the ones a
/// previous run left there that are still inside their hold window.
pub(crate) fn attach_taint_store(store: Arc<dyn tenzro_storage::KvStore>) {
    taint().attach(store, now_ms());
}

fn label(did: &str, source: String, at_ms: u64) {
    tracing::info!(target: "agent_guardrails", agent = %did, %source, "untrusted input reached the agent");
    taint().set(did, source, at_ms);
}

/// The label on `did` while it holds at `now_ms`.
pub(crate) fn taint_label(did: &str, now_ms: u64) -> Option<TaintLabel> {
    taint().get(did, now_ms)
}

/// Whether actions `did` proposes now derive from untrusted input.
pub(crate) fn is_tainted(did: &str) -> bool {
    taint_label(did, now_ms()).is_some()
}

/// Check that a delegated agent's terms allow `operation` now, recording a
/// refusal in its audit trail, and label the agent when the operation brings
/// in untrusted input. Agents with no terms on chain pass.
pub(crate) fn check_operation(
    node: &TenzroNode,
    did: &str,
    operation: &str,
    model: Option<String>,
) -> Result<(), String> {
    let Some(stored) = chain_terms(node, did) else {
        return Ok(());
    };
    let refused = crate::rpc::chain_state_of(node)
        .and_then(|chain| {
            tenzro_vm::native::check_agent_status(
                &chain,
                did,
                chrono::Utc::now().timestamp_millis().max(0) as u64,
            )
            .err()
        })
        .or_else(|| check_agent(node, did).err())
        .or_else(|| {
            check_scope(&stored.terms, &proposal(did, operation, model), now_ms())
                .err()
                .map(|d| format!("outside the agent's approved terms: {d}"))
        });
    match refused {
        Some(why) => Err(why),
        None => {
            if Exposure::of_operation(operation).untrusted_input {
                label(did, operation.to_string(), now_ms());
            }
            Ok(())
        }
    }
}

/// A delegated agent's bearer request must carry a typed intent: running a
/// model, or a free tool or skill invocation, which is checked by what it
/// runs once resolved. Anything else from a delegated agent, and any
/// request without an intent, is refused: its value moves only through
/// `tenzro_agentAct`. Agents with no terms on chain pass.
pub(crate) fn check_bearer_intent(
    node: &TenzroNode,
    did: &str,
    intent: Option<&tenzro_auth::AuthorityRequest>,
) -> Result<(), String> {
    if chain_terms(node, did).is_none() {
        return Ok(());
    }
    match bearer_proposal(intent)? {
        Proposal::Operation { operation, model } => check_operation(node, did, operation, model),
        _ => check_agent(node, did),
    }
}

/// The typed proposal a delegated agent's bearer request makes by its
/// intent, or why it makes none.
fn bearer_proposal(intent: Option<&tenzro_auth::AuthorityRequest>) -> Result<Proposal, String> {
    let Some(intent) = intent else {
        return Err(
            "a delegated agent acts only through typed actions; this request names none \
             (value moves through tenzro_agentAct)"
                .to_string(),
        );
    };
    let free = intent.constraint.amount.is_none_or(|a| a == 0);
    match intent.action {
        tenzro_auth::AuthorityAction::Inference if free => Ok(Proposal::Operation {
            operation: "inference",
            model: None,
        }),
        tenzro_auth::AuthorityAction::InvokeResource
            if free
                && intent
                    .constraint
                    .resource_id
                    .as_deref()
                    .is_some_and(|r| r.starts_with("tool:") || r.starts_with("skill:")) =>
        {
            Ok(Proposal::Invocation)
        }
        _ => Err(format!(
            "a delegated agent moves value only through tenzro_agentAct; {:?} is refused",
            intent.action
        )),
    }
}

/// The exposure a machine-access grant gives: any folder, device or
/// machine-internal network destination is private data.
fn grant_exposure(entry: &DelegationEntry) -> Exposure {
    Exposure {
        private_data: !entry.scope.machine_resources.is_empty(),
        ..Exposure::default()
    }
}

/// The exposure the live grants made out to `did` give.
fn grants_exposure(entries: &[DelegationEntry], did: &str) -> Exposure {
    entries
        .iter()
        .filter(|e| e.grantee_did == did && e.is_active())
        .fold(Exposure::default(), |acc, e| acc.with(grant_exposure(e)))
}

/// The terms chain state holds for `did`, when it is a delegated agent.
fn chain_terms(node: &TenzroNode, did: &str) -> Option<tenzro_vm::native::StoredAgentTerms> {
    let chain = crate::rpc::chain_state_of(node)?;
    tenzro_vm::native::read_agent_terms(&chain, did)
}

fn grant_entries(node: &TenzroNode) -> Vec<DelegationEntry> {
    node.egress().address_policy().grants().entries()
}

/// Refuse a delegated agent whose terms and grants together hold all three
/// exposures without the controller's exception. Agents with no terms on
/// chain pass.
pub(crate) fn check_agent(node: &TenzroNode, did: &str) -> Result<(), String> {
    let Some(stored) = chain_terms(node, did) else {
        return Ok(());
    };
    let exposure = stored
        .terms
        .exposure()
        .with(grants_exposure(&grant_entries(node), did));
    check_trifecta(exposure, stored.terms.trifecta_exception).map_err(str::to_string)
}

/// Refuse a machine-access grant to `grantee` with `resources` that would give
/// a delegated agent all three exposures without the controller's exception.
pub(crate) fn check_new_grant(
    node: &TenzroNode,
    grantee: &str,
    resources: &[tenzro_identity::MachineResource],
) -> Result<(), String> {
    let Some(stored) = chain_terms(node, grantee) else {
        return Ok(());
    };
    let added = Exposure {
        private_data: !resources.is_empty(),
        ..Exposure::default()
    };
    let exposure = stored
        .terms
        .exposure()
        .with(grants_exposure(&grant_entries(node), grantee))
        .with(added);
    check_trifecta(exposure, stored.terms.trifecta_exception).map_err(str::to_string)
}

/// The guardrail state of `did` for its status: each exposure, whether the
/// three combine, and whether the controller accepted that.
pub(crate) fn status(node: &Arc<TenzroNode>, did: &str) -> Value {
    let Some(stored) = chain_terms(node, did) else {
        return Value::Null;
    };
    let from_terms = stored.terms.exposure();
    let from_grants = grants_exposure(&grant_entries(node), did);
    let exposure = from_terms.with(from_grants);
    json!({
        "exposure": exposure,
        "exposure_from_grants": from_grants,
        "trifecta": exposure.is_trifecta(),
        "trifecta_exception": stored.terms.trifecta_exception,
        "refused": check_trifecta(exposure, stored.terms.trifecta_exception).is_err(),
        "tainted": taint_label(did, now_ms()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_identity::{DelegationScope, MachineResource};

    fn grant(to: &str) -> DelegationEntry {
        let scope = DelegationScope {
            machine_resources: vec![MachineResource::Folder {
                path: "/data".into(),
            }],
            ..DelegationScope::expiring_after(chrono::Duration::days(1))
        };
        DelegationEntry::new("did:tenzro:human:owner".into(), to.into(), scope)
    }

    #[test]
    fn a_folder_grant_completes_the_trifecta_for_a_fetching_agent() {
        let fetching = Exposure::of_operation("fetch");
        assert!(fetching.untrusted_input && fetching.external_egress);
        assert!(!fetching.is_trifecta());
        let entries = vec![grant("did:a"), grant("did:b")];
        let with_grants = fetching.with(grants_exposure(&entries, "did:a"));
        assert!(with_grants.is_trifecta());
        assert!(check_trifecta(with_grants, false).is_err());
        assert!(check_trifecta(with_grants, true).is_ok());
        let unrelated = fetching.with(grants_exposure(&entries, "did:c"));
        assert!(check_trifecta(unrelated, false).is_ok());
        let mut revoked = grant("did:c");
        revoked.revoke();
        assert!(!grants_exposure(&[revoked], "did:c").private_data);
    }

    fn intent(
        action: tenzro_auth::AuthorityAction,
        amount: Option<u128>,
        resource_id: Option<&str>,
    ) -> tenzro_auth::AuthorityRequest {
        tenzro_auth::AuthorityRequest {
            action,
            constraint: tenzro_auth::ResourceConstraint {
                asset: None,
                amount,
                counterparty: None,
                resource_id: resource_id.map(str::to_string),
            },
        }
    }

    #[test]
    fn every_agent_request_is_a_typed_proposal_or_refused() {
        assert_eq!(keyed_proposal("tenzro_agentAct", None), Ok(Proposal::Act));
        assert_eq!(
            keyed_proposal("tenzro_getBalance", None),
            Ok(Proposal::Read)
        );
        assert_eq!(keyed_proposal("eth_call", None), Ok(Proposal::Read));
        assert_eq!(
            keyed_proposal("tenzro_useTool", None),
            Ok(Proposal::Invocation)
        );
        let chat = json!({"model": "m1", "messages": []});
        assert_eq!(
            keyed_proposal("tenzro_chat", Some(&chat)),
            Ok(Proposal::Operation {
                operation: "inference",
                model: Some("m1".into())
            })
        );
        for free_form in [
            "tenzro_sendTransaction",
            "tenzro_acpCompleteCheckout",
            "tenzro_runWorkflow",
            "tenzro_addMachineAccess",
        ] {
            assert!(
                keyed_proposal(free_form, None).is_err(),
                "{free_form} must be refused"
            );
        }

        use tenzro_auth::AuthorityAction as A;
        assert!(
            bearer_proposal(None).is_err(),
            "a bearer request without an intent is refused"
        );
        assert_eq!(
            bearer_proposal(Some(&intent(A::InvokeResource, None, Some("tool:t1")))),
            Ok(Proposal::Invocation)
        );
        assert!(
            bearer_proposal(Some(&intent(A::InvokeResource, Some(5), Some("tool:t1")))).is_err()
        );
        assert!(
            bearer_proposal(Some(&intent(
                A::InvokeResource,
                None,
                Some("workflow_template:w")
            )))
            .is_err()
        );
        assert!(bearer_proposal(Some(&intent(A::Transfer, Some(1), None))).is_err());
        assert!(matches!(
            bearer_proposal(Some(&intent(A::Inference, None, None))),
            Ok(Proposal::Operation {
                operation: "inference",
                ..
            })
        ));
    }

    #[test]
    fn a_taint_label_holds_for_the_hold_window() {
        let did = "did:tenzro:machine:taint-test";
        assert!(taint_label(did, 1_000).is_none());
        label(did, "fetch".into(), 1_000);
        assert_eq!(
            taint_label(did, 1_000 + TAINT_HOLD_MS - 1).unwrap().source,
            "fetch"
        );
        assert!(taint_label(did, 1_000 + TAINT_HOLD_MS).is_none());
        assert!(Exposure::of_operation("fetch").untrusted_input);
        assert!(!Exposure::of_operation("inference").untrusted_input);
    }

    fn memory_store() -> Arc<dyn tenzro_storage::KvStore> {
        Arc::new(tenzro_storage::MemoryStore::new())
    }

    #[test]
    fn a_taint_label_survives_a_restart_inside_its_hold_window() {
        let store = memory_store();
        let before = TaintBook::default();
        before.attach(store.clone(), 1_000);
        before.set("did:tenzro:machine:a", "fetch".into(), 5_000);
        before.set("did:tenzro:machine:b", "web_search".into(), 6_000);
        drop(before);

        // A new process: nothing in memory, the same store.
        let after = TaintBook::default();
        assert!(after.get("did:tenzro:machine:a", 10_000).is_none());
        after.attach(store, 10_000);
        let a = after.get("did:tenzro:machine:a", 10_000).unwrap();
        assert_eq!((a.source.as_str(), a.at_ms), ("fetch", 5_000));
        assert_eq!(
            after.get("did:tenzro:machine:b", 10_000).unwrap().source,
            "web_search"
        );
        assert!(
            after
                .get("did:tenzro:machine:a", 5_000 + TAINT_HOLD_MS)
                .is_none(),
            "the hold window runs from when the input arrived, not from the restart"
        );
    }

    #[test]
    fn a_label_past_its_hold_window_is_not_restored_and_is_removed() {
        let store = memory_store();
        let before = TaintBook::default();
        before.attach(store.clone(), 1_000);
        before.set("did:tenzro:machine:old", "fetch".into(), 1_000);
        drop(before);

        let after = TaintBook::default();
        after.attach(store.clone(), 1_000 + TAINT_HOLD_MS);
        assert!(after.get("did:tenzro:machine:old", 1_000 + TAINT_HOLD_MS).is_none());
        let left = store
            .scan_prefix(tenzro_storage::CF_METADATA, TAINT_KEY_PREFIX.as_bytes())
            .unwrap();
        assert!(left.is_empty(), "the expired label is deleted");
    }

    #[test]
    fn a_label_set_before_the_store_is_bound_is_written_and_a_newer_one_stands() {
        let store = memory_store();
        let first = TaintBook::default();
        first.attach(store.clone(), 1_000);
        first.set("did:tenzro:machine:c", "fetch".into(), 2_000);
        drop(first);

        let book = TaintBook::default();
        book.set("did:tenzro:machine:c", "browse".into(), 9_000);
        book.set("did:tenzro:machine:d", "fetch".into(), 3_000);
        book.attach(store.clone(), 10_000);
        assert_eq!(book.get("did:tenzro:machine:c", 10_000).unwrap().source, "browse");

        let restarted = TaintBook::default();
        restarted.attach(store, 10_000);
        assert_eq!(
            restarted.get("did:tenzro:machine:c", 10_000).unwrap().at_ms,
            9_000
        );
        assert!(restarted.get("did:tenzro:machine:d", 10_000).is_some());
    }

    #[test]
    fn a_book_with_no_store_still_holds_labels() {
        let book = TaintBook::default();
        book.set("did:tenzro:machine:e", "fetch".into(), 1_000);
        assert!(book.get("did:tenzro:machine:e", 1_000).is_some());
    }
}
