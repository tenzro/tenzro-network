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
use tenzro_payments::terms_gate::TAINT_HOLD_MS;
use tenzro_types::agent_terms::{AgentAction, Exposure, check_scope, check_trifecta};

use crate::node::TenzroNode;

/// RPC methods that run a model: the `inference` operation.
pub(crate) const MODEL_METHODS: &[&str] = &[
    "tenzro_chat",
    "tenzro_inference",
    "tenzro_generate",
    "tenzro_textEmbed",
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

/// Where untrusted input last reached an agent on this node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct TaintLabel {
    /// The operation that brought it in.
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
                    let newer = labels
                        .get(did)
                        .is_some_and(|l| l.at_ms >= stored_label.at_ms);
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

/// A request refused to a delegated agent: the rule that stopped it, for
/// the node's metrics, and the reason given to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    /// One of `status` (revoked, quarantined or paused), `expiry`,
    /// `serving_node`, `intent`, `event_filter`, `exposure`, `step_up` or
    /// `terms`.
    pub(crate) reason: &'static str,
    pub(crate) why: String,
}

/// A refusal under `reason` with the message it came with.
pub(crate) fn refused(reason: &'static str) -> impl Fn(String) -> Refused {
    move |why| Refused { reason, why }
}

/// Most delegated agents whose spend the node reports; past it the agent
/// served longest ago gives way.
const MAX_REPORTED_AGENTS: usize = 4096;

/// Counts of what the node refused its delegated agents and of the untrusted
/// input that reached them, since the node started.
#[derive(Default)]
pub(crate) struct GuardrailCounters {
    refusals: parking_lot::Mutex<std::collections::BTreeMap<&'static str, u64>>,
    taints: parking_lot::Mutex<std::collections::BTreeMap<String, u64>>,
    /// Delegated agents whose requests this node has checked, at most
    /// [`MAX_REPORTED_AGENTS`].
    agents: parking_lot::Mutex<ServedAgents>,
}

/// Agents in the order they were last served: each agent's latest serve
/// number, and the agents by that number, so serving one again and letting
/// the longest-unserved go both cost a map update, not a scan.
#[derive(Default)]
struct ServedAgents {
    next: u64,
    by_did: std::collections::HashMap<String, u64>,
    by_order: std::collections::BTreeMap<u64, String>,
}

impl ServedAgents {
    fn serve(&mut self, did: &str) {
        let order = self.next;
        self.next += 1;
        if let Some(previous) = self.by_did.get_mut(did) {
            let name = self.by_order.remove(previous).expect("indexed both ways");
            *previous = order;
            self.by_order.insert(order, name);
            return;
        }
        if self.by_did.len() == MAX_REPORTED_AGENTS
            && let Some((_, oldest)) = self.by_order.pop_first()
        {
            self.by_did.remove(&oldest);
        }
        self.by_did.insert(did.to_string(), order);
        self.by_order.insert(order, did.to_string());
    }

    /// The agents, longest-unserved first.
    fn iter(&self) -> impl Iterator<Item = &String> {
        self.by_order.values()
    }
}

/// The share of its daily spend limit an agent has used, as a band; agents
/// are counted by band and never named.
fn spend_band(spent: u128, cap: Option<u128>) -> &'static str {
    let Some(cap) = cap else {
        return "uncapped";
    };
    if spent >= cap {
        "at_limit"
    } else if spent >= cap - cap / 5 {
        "from_80_percent"
    } else if spent >= cap / 2 {
        "from_50_percent"
    } else {
        "under_50_percent"
    }
}

impl GuardrailCounters {
    fn refused(&self, reason: &'static str) {
        *self.refusals.lock().entry(reason).or_default() += 1;
    }

    fn tainted(&self, source: &str) {
        *self
            .taints
            .lock()
            .entry(source.to_ascii_lowercase())
            .or_default() += 1;
    }

    fn served(&self, did: &str) {
        self.agents.lock().serve(did);
    }

    /// Both counters in Prometheus text format.
    fn encode_prometheus(&self, out: &mut String) {
        out.push_str(
            "# HELP tenzro_agent_refusals_total Requests refused to delegated agents, by the \
             rule that stopped them\n",
        );
        out.push_str("# TYPE tenzro_agent_refusals_total counter\n");
        for (reason, n) in self.refusals.lock().iter() {
            out.push_str(&format!(
                "tenzro_agent_refusals_total{{reason=\"{reason}\"}} {n}\n"
            ));
        }
        out.push('\n');
        out.push_str(
            "# HELP tenzro_agent_taint_events_total Times untrusted input reached a delegated \
             agent, by the operation that brought it in\n",
        );
        out.push_str("# TYPE tenzro_agent_taint_events_total counter\n");
        for (source, n) in self.taints.lock().iter() {
            out.push_str(&format!(
                "tenzro_agent_taint_events_total{{source=\"{source}\"}} {n}\n"
            ));
        }
        out.push('\n');
    }
}

fn counters() -> &'static GuardrailCounters {
    static COUNTERS: std::sync::OnceLock<GuardrailCounters> = std::sync::OnceLock::new();
    COUNTERS.get_or_init(Default::default)
}

/// Counts `checked` under its rule when it is a refusal, and hands back the
/// reason given to the caller.
pub(crate) fn counted(checked: Result<(), Refused>) -> Result<(), String> {
    checked.map_err(|r| {
        counters().refused(r.reason);
        r.why
    })
}

/// The agent refusal and taint counters in Prometheus text format.
pub(crate) fn encode_prometheus(out: &mut String) {
    counters().encode_prometheus(out);
}

/// How many of the delegated agents this node has served since it started
/// sit in each band of their daily spend limit, in Prometheus text format.
/// Spend and limit are read from chain state at the time of the call.
pub(crate) fn encode_spend_prometheus(node: &TenzroNode, out: &mut String) {
    let Some(chain) = crate::rpc::chain_state_of(node) else {
        return;
    };
    let now = now_ms();
    let mut bands = std::collections::BTreeMap::new();
    let served: Vec<String> = counters().agents.lock().iter().cloned().collect();
    for did in &served {
        let Some(stored) = tenzro_vm::native::read_agent_terms(&chain, did) else {
            continue;
        };
        let cap = stored
            .terms
            .delegation_scope
            .max_daily_spend
            .as_deref()
            .and_then(|v| v.parse::<u128>().ok());
        let spent = tenzro_vm::native::read_agent_spent(&chain, did, now);
        *bands.entry(spend_band(spent, cap)).or_insert(0u64) += 1;
    }
    out.push_str(
        "# HELP tenzro_agent_daily_spend_agents Delegated agents served since start, by the \
         share of their daily spend limit used\n",
    );
    out.push_str("# TYPE tenzro_agent_daily_spend_agents gauge\n");
    for (band, n) in bands {
        out.push_str(&format!(
            "tenzro_agent_daily_spend_agents{{used=\"{band}\"}} {n}\n"
        ));
    }
    out.push('\n');
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
    counters().tainted(&source);
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
) -> Result<(), Refused> {
    let Some(stored) = chain_terms(node, did) else {
        return Ok(());
    };
    counters().served(did);
    let refusal = crate::rpc::chain_state_of(node)
        .and_then(|chain| {
            tenzro_vm::native::check_agent_status(
                &chain,
                did,
                chrono::Utc::now().timestamp_millis().max(0) as u64,
            )
            .err()
        })
        .map(refused("status"))
        .or_else(|| check_agent(node, did).err())
        .or_else(|| {
            check_scope(&stored.terms, &proposal(did, operation, model), now_ms())
                .err()
                .map(|d| Refused {
                    reason: if d.starts_with("step-up required") {
                        "step_up"
                    } else {
                        "terms"
                    },
                    why: format!("outside the agent's approved terms: {d}"),
                })
        });
    match refusal {
        Some(r) => Err(r),
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
) -> Result<(), Refused> {
    if chain_terms(node, did).is_none() {
        return Ok(());
    }
    match bearer_proposal(intent).map_err(refused("intent"))? {
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
pub(crate) fn check_agent(node: &TenzroNode, did: &str) -> Result<(), Refused> {
    let Some(stored) = chain_terms(node, did) else {
        return Ok(());
    };
    let exposure = stored
        .terms
        .exposure()
        .with(grants_exposure(&grant_entries(node), did));
    check_trifecta(exposure, stored.terms.trifecta_exception)
        .map_err(|why| refused("exposure")(why.to_string()))
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
    fn an_agent_is_placed_by_the_share_of_its_daily_limit_it_has_used() {
        assert_eq!(spend_band(0, None), "uncapped");
        assert_eq!(spend_band(u128::MAX, None), "uncapped");
        assert_eq!(spend_band(0, Some(100)), "under_50_percent");
        assert_eq!(spend_band(49, Some(100)), "under_50_percent");
        assert_eq!(spend_band(50, Some(100)), "from_50_percent");
        assert_eq!(spend_band(79, Some(100)), "from_50_percent");
        assert_eq!(spend_band(80, Some(100)), "from_80_percent");
        assert_eq!(spend_band(99, Some(100)), "from_80_percent");
        assert_eq!(spend_band(100, Some(100)), "at_limit");
        assert_eq!(spend_band(101, Some(100)), "at_limit");
        assert_eq!(spend_band(0, Some(0)), "at_limit");
        let big = u128::MAX;
        assert_eq!(spend_band(big - 1, Some(big)), "from_80_percent");
        assert_eq!(spend_band(big / 2 - 1, Some(big)), "under_50_percent");
    }

    #[test]
    fn refusals_and_taint_events_are_counted_by_the_rule_and_the_source() {
        let c = GuardrailCounters::default();
        for reason in ["status", "expiry", "terms", "terms", "step_up", "exposure"] {
            c.refused(reason);
        }
        c.tainted("fetch");
        c.tainted("Fetch");
        c.tainted("browse");

        let mut out = String::new();
        c.encode_prometheus(&mut out);
        for line in [
            "# TYPE tenzro_agent_refusals_total counter",
            "tenzro_agent_refusals_total{reason=\"status\"} 1",
            "tenzro_agent_refusals_total{reason=\"expiry\"} 1",
            "tenzro_agent_refusals_total{reason=\"terms\"} 2",
            "tenzro_agent_refusals_total{reason=\"step_up\"} 1",
            "tenzro_agent_refusals_total{reason=\"exposure\"} 1",
            "# TYPE tenzro_agent_taint_events_total counter",
            "tenzro_agent_taint_events_total{source=\"fetch\"} 2",
            "tenzro_agent_taint_events_total{source=\"browse\"} 1",
        ] {
            assert!(out.lines().any(|l| l == line), "missing {line} in\n{out}");
        }
    }

    /// The count follows the rule that refused, whatever the message says:
    /// a message that reads like another rule is counted under its own.
    #[test]
    fn a_refusal_is_counted_under_its_rule_and_its_message_handed_back() {
        let read = |name: &str| {
            let mut out = String::new();
            encode_prometheus(&mut out);
            out.lines()
                .find_map(|l| l.strip_prefix(name))
                .map_or(0, |n| n.trim().parse::<u64>().unwrap())
        };
        let intent = "tenzro_agent_refusals_total{reason=\"intent\"}";
        let status = "tenzro_agent_refusals_total{reason=\"status\"}";
        let tainted = "tenzro_agent_taint_events_total{source=\"web_search\"}";
        let (i0, s0, t0) = (read(intent), read(status), read(tainted));

        assert_eq!(counted(Ok(())), Ok(()));
        let why = "did:tenzro:machine:counted is quarantined".to_string();
        assert_eq!(counted(Err(refused("intent")(why.clone()))), Err(why));
        label("did:tenzro:machine:counted", "web_search".into(), 1_000);

        assert_eq!(read(intent), i0 + 1);
        assert_eq!(read(status), s0, "not counted by what the message says");
        assert_eq!(read(tainted), t0 + 1);
    }

    #[test]
    fn the_agents_reported_are_bounded_and_the_most_recent_kept() {
        let c = GuardrailCounters::default();
        for n in 0..MAX_REPORTED_AGENTS + 10 {
            c.served(&format!("did:tenzro:machine:{n}"));
        }
        // Serving an agent again moves it to the back rather than adding it.
        c.served("did:tenzro:machine:20");
        let agents = c.agents.lock();
        assert_eq!(agents.by_did.len(), MAX_REPORTED_AGENTS);
        assert_eq!(
            agents.iter().next().map(String::as_str),
            Some("did:tenzro:machine:10")
        );
        assert_eq!(
            agents.iter().last().map(String::as_str),
            Some("did:tenzro:machine:20")
        );
        assert_eq!(agents.by_order.len(), MAX_REPORTED_AGENTS);
        assert_eq!(
            agents
                .iter()
                .filter(|d| *d == "did:tenzro:machine:20")
                .count(),
            1
        );
        assert!(!agents.iter().any(|d| d == "did:tenzro:machine:9"));
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
        assert!(
            after
                .get("did:tenzro:machine:old", 1_000 + TAINT_HOLD_MS)
                .is_none()
        );
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
        assert_eq!(
            book.get("did:tenzro:machine:c", 10_000).unwrap().source,
            "browse"
        );

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
