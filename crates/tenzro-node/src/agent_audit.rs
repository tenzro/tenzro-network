//! Chain-state views of the agent audit trail, and a validator's watch over
//! it.
//!
//! Agents' actions are recorded by whoever runs the agent, outside the node:
//! the recorder appends signed entries to the agent's sessions and commits a
//! root over them once per epoch in an `AgentAuditCommit` transaction. The
//! node keeps what consensus decides: quarantines and revocations, which every
//! node enforces from chain state, and the committed roots and their hardware
//! attestations. A validator checks every committer's roots each epoch and
//! flags what does not hold.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use tenzro_storage::KvStore;
use tenzro_types::agent_audit::parse_digest;
use tracing::{info, warn};

use crate::node::TenzroNode;
use crate::rpc::{AuthContext, AuthOutcome, JsonRpcError, authenticate_bearer};

/// How often the watcher looks for an epoch that ended.
const WATCH_POLL: Duration = Duration::from_secs(60);

/// The quarantine and revocation state chain state holds for agents, and the
/// session lines this node commits each epoch.
#[derive(Default)]
pub struct AgentAudit {
    storage: OnceLock<Arc<dyn KvStore>>,
    book: EpochBook,
}

/// The audit sessions this node supervised, per epoch: each session's latest
/// line (its MMR root and entry count) reported in that epoch. The node
/// commits an epoch's lines once the epoch has ended.
#[derive(Debug, Default)]
pub struct EpochBook {
    epochs: parking_lot::Mutex<
        std::collections::BTreeMap<
            u64,
            std::collections::BTreeMap<[u8; 32], tenzro_types::agent_audit::SessionLeaf>,
        >,
    >,
}

impl EpochBook {
    /// Record `line` as its session's latest in `epoch`. A session's log only
    /// grows: a line covering fewer entries than one already recorded for it,
    /// or a different root over as many, is refused.
    pub fn record(
        &self,
        epoch: u64,
        line: tenzro_types::agent_audit::SessionLeaf,
    ) -> Result<usize, String> {
        let mut epochs = self.epochs.lock();
        for (e, lines) in epochs.iter() {
            if let Some(prior) = lines.get(&line.session_id) {
                let shrinks = line.count < prior.count;
                let forks = line.count == prior.count && line.mmr_root != prior.mmr_root;
                if shrinks || forks {
                    return Err(format!(
                        "session {} already recorded {} entries under another root in epoch {e}",
                        hex::encode(line.session_id),
                        prior.count
                    ));
                }
            }
        }
        if line.count == 0 {
            return Err("a session line covers at least one entry".into());
        }
        let lines = epochs.entry(epoch).or_default();
        lines.insert(line.session_id, line);
        Ok(lines.len())
    }

    /// The ended epochs (before `current`) still within the commit window,
    /// each with its lines ordered by session id, that `committed` does not
    /// already hold. Epochs past the window are dropped and returned apart.
    pub fn due(
        &self,
        current: u64,
        committed: impl Fn(u64) -> bool,
    ) -> (
        Vec<(u64, Vec<tenzro_types::agent_audit::SessionLeaf>)>,
        Vec<u64>,
    ) {
        let window = tenzro_vm::native::AGENT_AUDIT_COMMIT_WINDOW;
        let mut epochs = self.epochs.lock();
        let lapsed: Vec<u64> = epochs
            .keys()
            .copied()
            .filter(|e| *e < current && current - e > window)
            .collect();
        for e in &lapsed {
            epochs.remove(e);
        }
        let done: Vec<u64> = epochs
            .keys()
            .copied()
            .filter(|e| *e < current && committed(*e))
            .collect();
        for e in &done {
            epochs.remove(e);
        }
        let due = epochs
            .range(..current)
            .map(|(e, lines)| (*e, lines.values().cloned().collect()))
            .collect();
        (due, lapsed)
    }

    /// Forget `epoch`, once its commitment is on chain.
    pub fn committed(&self, epoch: u64) {
        self.epochs.lock().remove(&epoch);
    }
}

/// The `AgentAuditCommit` for `epoch` over `lines`, with the machine's
/// attestation over `(epoch, root)` (empty on a machine with no TPM).
pub fn commit_transaction(
    epoch: u64,
    lines: &[tenzro_types::agent_audit::SessionLeaf],
    attestation: Vec<u8>,
) -> tenzro_types::TransactionType {
    tenzro_types::TransactionType::AgentAuditCommit {
        epoch,
        root: tenzro_types::agent_audit::epoch_root(lines).to_vec(),
        sessions: lines.len() as u64,
        entries_ref: String::new(),
        attestation,
    }
}

impl std::fmt::Debug for AgentAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentAudit")
            .field("bound", &self.storage.get().is_some())
            .finish()
    }
}

impl AgentAudit {
    /// The store chain state is read from.
    pub(crate) fn bind_storage(&self, storage: Arc<dyn KvStore>) {
        let _ = self.storage.set(storage);
    }

    /// Whether chain state records `did` as quarantined.
    pub(crate) fn is_quarantined(&self, did: &str) -> bool {
        self.chain_quarantine(did).is_some()
    }

    /// Whether chain state records `did` as revoked by its controller: the
    /// same agent-status record a quarantine writes, marked permanent.
    pub(crate) fn is_revoked(&self, did: &str) -> bool {
        self.chain_quarantine(did).is_some_and(|q| q.revoked)
    }

    /// Chain state, read from the bound store.
    pub(crate) fn chain(&self) -> Option<tenzro_vm::StateAdapter> {
        self.storage
            .get()
            .map(|s| tenzro_vm::StateAdapter::with_storage(s.clone()))
    }

    /// The session lines this node commits each epoch.
    pub fn book(&self) -> &EpochBook {
        &self.book
    }

    fn chain_quarantine(&self, did: &str) -> Option<tenzro_vm::native::AgentQuarantine> {
        let storage = self.storage.get()?.clone();
        let chain = tenzro_vm::StateAdapter::with_storage(storage);
        tenzro_vm::native::read_agent_quarantine(&chain, did)
    }
}

/// On a validator, check the audit commitments and bridge reserves of every
/// epoch that ends.
pub fn spawn_watchers(node: &Arc<TenzroNode>) {
    if !node.config().roles.is_validator() {
        return;
    }
    let weak = Arc::downgrade(node);
    tokio::spawn(async move {
        let mut seen: Option<u64> = None;
        loop {
            tokio::time::sleep(WATCH_POLL).await;
            let Some(node) = weak.upgrade() else { return };
            let Some(chain) = crate::rpc::chain_state_of(&node) else {
                continue;
            };
            let Ok(rs) = tenzro_vm::native::read_reward_state(&chain) else {
                continue;
            };
            let current = rs.current_epoch;
            let ended = match seen {
                Some(prev) if current > prev => prev,
                None => {
                    seen = Some(current);
                    continue;
                }
                _ => continue,
            };
            seen = Some(current);
            watch_peers(&node, current).await;
            crate::bridge_reserve::watch_reserves(&node, ended).await;
        }
    });
}

/// Commit the audit sessions this node supervised, once per ended epoch:
/// every `WATCH_POLL`, each epoch the book holds that has ended and is not on
/// chain yet goes out as one `AgentAuditCommit` from this node's account,
/// attested by its TPM where it has one.
pub fn spawn_committer(node: &Arc<TenzroNode>) {
    let weak = Arc::downgrade(node);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WATCH_POLL).await;
            let Some(node) = weak.upgrade() else { return };
            commit_due(&node).await;
        }
    });
}

async fn commit_due(node: &Arc<TenzroNode>) {
    let Some(submitter) = node.ledger_submitter() else {
        return;
    };
    let Some(chain) = crate::rpc::chain_state_of(node) else {
        return;
    };
    let Ok(rs) = tenzro_vm::native::read_reward_state(&chain) else {
        return;
    };
    let me = submitter.address().as_bytes().to_vec();
    let (due, lapsed) = node.agent_audit().book().due(rs.current_epoch, |e| {
        tenzro_vm::native::read_agent_audit(&chain, &me, e).is_some()
    });
    for epoch in lapsed {
        warn!(target: "agent_audit", epoch, "audit sessions were not committed within the window");
    }
    for (epoch, lines) in due {
        let root = tenzro_types::agent_audit::epoch_root(&lines);
        let attestation = attest(epoch, root).await;
        let tx = commit_transaction(epoch, &lines, attestation);
        match submitter
            .submit_with_gas(
                submitter.address(),
                tx,
                tenzro_vm::native::GAS_AGENT_AUDIT_COMMIT * 2,
            )
            .await
        {
            Ok(_) => {
                node.agent_audit().book().committed(epoch);
                if let Err(e) =
                    node.tool_calls()
                        .committed(&crate::tool_call_record::CommittedEpoch {
                            epoch,
                            committer: format!("0x{}", hex::encode(submitter.address().as_bytes())),
                            lines: lines.clone(),
                        })
                {
                    warn!(target: "agent_audit", epoch, "committed lines not kept: {e}");
                }
                info!(target: "agent_audit", epoch, sessions = lines.len(), "committed the epoch's audit sessions");
            }
            Err(e) => {
                warn!(target: "agent_audit", epoch, error = %e, "could not commit the epoch's audit sessions")
            }
        }
    }
}

/// This machine's TPM quote over `(epoch, root)`, as the commitment carries
/// it. A machine without a TPM commits with no attestation, which chain
/// state records and validators report as unattested.
async fn attest(epoch: u64, root: [u8; 32]) -> Vec<u8> {
    let digest = tenzro_types::agent_audit::commit_attestation_digest(epoch, &root);
    match quote(digest).await {
        Ok((machine_did, evidence)) => serde_json::to_vec(
            &json!({ "kind": "tpm", "machine_did": machine_did, "evidence": evidence }),
        )
        .unwrap_or_default(),
        Err(e) => {
            warn!(target: "agent_audit", epoch, error = %e, "committing without a TPM attestation");
            Vec::new()
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
async fn quote(digest: [u8; 32]) -> Result<(String, tenzro_tee::tpm_attest::TpmEvidence), String> {
    tokio::task::spawn_blocking(move || tenzro_tee::tpm_attest::quote_local_machine(&digest))
        .await
        .map_err(|e| format!("TPM quote task failed: {e}"))?
        .map_err(|e| format!("TPM quote failed: {e}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn quote(_digest: [u8; 32]) -> Result<(String, tenzro_tee::tpm_attest::TpmEvidence), String> {
    Err("this machine has no TPM 2.0 resource manager to quote with".into())
}

/// `tenzro_recordAgentAuditSession` — `session_id`, `mmr_root`, `count`: the
/// latest line of an agent audit session this node supervises, reported by
/// the agent's runtime on this machine. The node commits it with the epoch's
/// other sessions once the epoch ends.
pub(crate) async fn handle_record_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let field = |k: &str| {
        params
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| bad(format!("Missing '{k}'")))
    };
    let session_id =
        parse_digest(field("session_id")?).map_err(|e| bad(format!("session_id: {e}")))?;
    let mmr_root = parse_digest(field("mmr_root")?).map_err(|e| bad(format!("mmr_root: {e}")))?;
    let count = params
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("Missing 'count'"))?;
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Chain state unavailable".to_string(),
        data: None,
    })?;
    let epoch = tenzro_vm::native::read_reward_state(&chain)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: e.to_string(),
            data: None,
        })?
        .current_epoch;
    let line = tenzro_types::agent_audit::SessionLeaf {
        session_id,
        mmr_root,
        count,
    };
    let sessions = node.agent_audit().book().record(epoch, line).map_err(bad)?;
    Ok(json!({ "epoch": epoch, "sessions": sessions }))
}

/// Check every other node's committed roots for the epoch that just ended,
/// and flag what does not hold: a node that stopped committing, an
/// attestation that does not verify, or a measured boot state that changed.
async fn watch_peers(node: &Arc<TenzroNode>, current: u64) {
    use tenzro_types::agent_audit::AuditFinding;
    use tenzro_vm::native::{AGENT_AUDIT_COMMIT_WINDOW, read_agent_audit};
    let Some(chain) = crate::rpc::chain_state_of(node) else {
        return;
    };
    let me = node
        .ledger_submitter()
        .map(|s| hex::encode(s.address().as_bytes()))
        .unwrap_or_default();
    let ended = current.saturating_sub(1);
    let pcr = |c: &[u8], epoch: u64| -> Option<String> {
        let r = read_agent_audit(&chain, c, epoch)?;
        let att = hex::decode(&r.attestation).ok()?;
        let v = verify_attestation(epoch, &r.root, &att).ok()?;
        v["pcr_digest"].as_str().map(str::to_string)
    };
    let mut findings = Vec::new();
    for committer in tenzro_vm::native::agent_audit_committers(&chain) {
        if committer == me {
            continue;
        }
        let Ok(c) = hex::decode(&committer) else {
            continue;
        };
        let name = format!("0x{committer}");
        if let Some(t) = current.checked_sub(AGENT_AUDIT_COMMIT_WINDOW + 1)
            && t > 0
            && read_agent_audit(&chain, &c, t - 1).is_some()
            && read_agent_audit(&chain, &c, t).is_none()
        {
            findings.push(AuditFinding::MissingCommit {
                committer: name.clone(),
                epoch: t,
            });
        }
        let Some(record) = read_agent_audit(&chain, &c, ended) else {
            continue;
        };
        let Ok(att) = hex::decode(&record.attestation) else {
            continue;
        };
        match verify_attestation(ended, &record.root, &att) {
            Err(_) => findings.push(AuditFinding::AttestationInvalid {
                committer: name,
                epoch: ended,
            }),
            Ok(v) => {
                let now = v["pcr_digest"].as_str().map(str::to_string);
                let before = (1..=AGENT_AUDIT_COMMIT_WINDOW + 1)
                    .filter_map(|back| ended.checked_sub(back))
                    .find_map(|e| pcr(&c, e));
                if let (Some(now), Some(before)) = (now, before)
                    && now != before
                {
                    findings.push(AuditFinding::ImageChanged {
                        committer: name,
                        epoch: ended,
                    });
                }
            }
        }
    }
    if findings.is_empty() {
        return;
    }
    findings.truncate(tenzro_types::agent_audit::MAX_FINDINGS);
    submit_flag(node, ended, findings).await.ok();
}

/// Where a background component (a training task, the trust ledger) sends a
/// finding it proved: this validator's ledger submitter once it is up, and
/// the chain state the current epoch is read from. A node that is not a
/// validator never fills the slot, and its findings go nowhere: only bonded
/// stake can make a finding take effect.
#[derive(Clone)]
pub(crate) struct FindingSink {
    submitter: Arc<std::sync::OnceLock<Arc<crate::payment_rails::LedgerSubmitter>>>,
    storage: Arc<dyn tenzro_storage::KvStore>,
}

impl FindingSink {
    pub(crate) fn new(
        submitter: Arc<std::sync::OnceLock<Arc<crate::payment_rails::LedgerSubmitter>>>,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        Self { submitter, storage }
    }

    /// Flag `finding` in the current epoch from this validator's account.
    pub(crate) async fn flag(&self, finding: tenzro_types::agent_audit::AuditFinding) {
        let Some(submitter) = self.submitter.get() else {
            return;
        };
        let chain = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
        let Ok(rs) = tenzro_vm::native::read_reward_state(&chain) else {
            return;
        };
        let gas =
            tenzro_vm::native::GAS_AGENT_AUDIT_FLAG + tenzro_vm::native::GAS_AGENT_AUDIT_FINDING;
        let tx = tenzro_types::TransactionType::AgentAuditFlag {
            epoch: rs.current_epoch,
            findings: vec![finding],
        };
        match submitter
            .submit_with_gas(submitter.address(), tx, gas)
            .await
        {
            Ok(_) => {
                info!(target: "agent_audit", epoch = rs.current_epoch, "flagged a proven finding")
            }
            Err(e) => warn!(target: "agent_audit", error = %e, "could not flag a proven finding"),
        }
    }
}

/// Submit findings from this validator's account.
pub(crate) async fn submit_flag(
    node: &Arc<TenzroNode>,
    epoch: u64,
    findings: Vec<tenzro_types::agent_audit::AuditFinding>,
) -> Result<Value, JsonRpcError> {
    let count = findings.len();
    let gas = tenzro_vm::native::GAS_AGENT_AUDIT_FLAG
        + tenzro_vm::native::GAS_AGENT_AUDIT_FINDING * count as u64;
    let tx = tenzro_types::TransactionType::AgentAuditFlag { epoch, findings };
    let result = crate::rpc::submit_as_validator(node, tx, gas).await;
    match &result {
        Ok(_) => info!(target: "agent_audit", epoch, count, "flagged audit findings"),
        Err(e) => {
            warn!(target: "agent_audit", epoch, error = %e.message, "could not flag audit findings")
        }
    }
    result
}

/// `tenzro_flagAgentAudit` — `epoch`, `findings`: submit this validator's
/// findings, such as quarantining an agent on the network's authority or
/// tripping the bridge circuit breaker. They take effect once validators
/// holding two thirds of bonded stake have made them.
pub(crate) async fn handle_flag(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let epoch = params
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("Missing 'epoch'"))?;
    let findings: Vec<tenzro_types::agent_audit::AuditFinding> = serde_json::from_value(
        params
            .get("findings")
            .cloned()
            .ok_or_else(|| bad("Missing 'findings'"))?,
    )
    .map_err(|e| bad(format!("findings: {e}")))?;
    if findings.is_empty() || findings.len() > tenzro_types::agent_audit::MAX_FINDINGS {
        return Err(bad("findings must hold 1 to 256 entries"));
    }
    submit_flag(node, epoch, findings).await
}

/// `tenzro_getAgentQuarantine` — `agent_did`: the quarantine chain state
/// holds and, for a delegated agent, its guardrail state.
pub(crate) async fn handle_get_quarantine(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let did = params
        .get("agent_did")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'agent_did'"))?;
    let on_chain = node.agent_audit().chain_quarantine(did);
    Ok(json!({
        "agent_did": did,
        "quarantined": on_chain.is_some(),
        "on_chain": on_chain,
        "guardrails": crate::agent_guardrails::status(node, did),
    }))
}

/// `tenzro_getBridgeCircuit` — `source_chain`, optional `adapter`: the
/// circuit-breaker pauses chain state holds for the routes to and from
/// `source_chain`, one adapter's or every adapter's.
pub(crate) async fn handle_get_bridge_circuit(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::bridge_route::BridgeRouteAdapter;
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let source_chain = params
        .get("source_chain")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'source_chain'"))?
        .to_ascii_lowercase();
    let adapters: Vec<BridgeRouteAdapter> = match params.get("adapter").and_then(Value::as_str) {
        Some(name) => vec![
            BridgeRouteAdapter::parse(name)
                .ok_or_else(|| bad(format!("'{name}' is not a governed bridge adapter")))?,
        ],
        None => BridgeRouteAdapter::ALL.to_vec(),
    };
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Chain state unavailable".to_string(),
        data: None,
    })?;
    let stops: Vec<_> = adapters
        .iter()
        .filter_map(|a| tenzro_vm::native::read_bridge_circuit(&chain, *a, &source_chain))
        .collect();
    Ok(json!({
        "source_chain": source_chain,
        "paused": stops.iter().any(|s| s.mode == tenzro_types::bridge_route::BridgeRouteMode::Paused),
        "disabled": stops.iter().any(|s| s.mode == tenzro_types::bridge_route::BridgeRouteMode::Disabled),
        "stops": stops,
    }))
}

/// Check a commitment's attestation: the quote verifies under the machine's
/// attestation key and quotes exactly `(epoch, root)`.
pub(crate) fn verify_attestation(
    epoch: u64,
    root_hex: &str,
    attestation: &[u8],
) -> Result<Value, String> {
    if attestation.is_empty() {
        return Ok(json!({ "attested": false, "reason": "the machine has no TPM" }));
    }
    let root = parse_digest(root_hex)?;
    let doc: Value = serde_json::from_slice(attestation).map_err(|e| e.to_string())?;
    if doc["kind"] != "tpm" {
        return Err(format!("unknown attestation kind {}", doc["kind"]));
    }
    let evidence: tenzro_tee::tpm_attest::TpmEvidence =
        serde_json::from_value(doc["evidence"].clone()).map_err(|e| e.to_string())?;
    let digest = tenzro_types::agent_audit::commit_attestation_digest(epoch, &root);
    let quote =
        tenzro_tee::tpm_attest::verify_quote(&evidence, &digest).map_err(|e| e.to_string())?;
    let ak = tenzro_tee::tpm_attest::attestation_key_sec1(&evidence).map_err(|e| e.to_string())?;
    let machine_did = tenzro_tee::tpm_attest::machine_did_for_attestation_key(&ak);
    if doc["machine_did"].as_str() != Some(machine_did.as_str()) {
        return Err("the attestation names a machine its key does not derive".into());
    }
    Ok(json!({
        "attested": true,
        "machine_did": machine_did,
        "ek_name": hex::encode(&quote.ek_name),
        "pcr_digest": hex::encode(&quote.pcr_digest),
        "reset_count": quote.reset_count,
        "firmware_version": quote.firmware_version,
    }))
}

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// On a private node, an agent's evidence is disclosed only to its
/// controller, authenticated by their bearer.
pub(crate) async fn may_read(
    node: &Arc<TenzroNode>,
    auth_ctx: &AuthContext,
    controller: Option<&str>,
) -> Result<(), JsonRpcError> {
    if !crate::identity_bootstrap::is_private(&node.visibility()) {
        return Ok(());
    }
    match authenticate_bearer(node, auth_ctx, None).await {
        AuthOutcome::Authenticated { bearer_did, .. }
            if Some(bearer_did.as_str()) == controller =>
        {
            Ok(())
        }
        AuthOutcome::AuthError(e) => Err(e),
        _ => Err(JsonRpcError {
            code: -32001,
            message: "This node is private: an agent's evidence is disclosed only to its \
                      controller."
                .to_string(),
            data: None,
        }),
    }
}

/// `tenzro_getAgentAuditCommit` — `committer`, `epoch`: the root recorded on
/// chain. Served from chain state, so any node answers it.
pub(crate) async fn handle_get_commit(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let committer = params
        .get("committer")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'committer'"))?;
    let committer = hex::decode(committer.strip_prefix("0x").unwrap_or(committer))
        .map_err(|e| bad(format!("committer: {e}")))?;
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Chain state unavailable".to_string(),
        data: None,
    })?;
    let last = tenzro_vm::native::last_agent_audit_epoch(&chain, &committer);
    let epoch = params.get("epoch").and_then(Value::as_u64).or(last);
    let record = epoch.and_then(|e| tenzro_vm::native::read_agent_audit(&chain, &committer, e));
    Ok(json!({
        "committer": format!("0x{}", hex::encode(&committer)),
        "epoch": epoch,
        "record": record,
        "last_epoch": last,
    }))
}

/// `tenzro_verifyAgentAuditAttestation` — `committer`, `epoch`: check the
/// hardware attestation over the commitment recorded on chain. Served from
/// chain state, so any node answers it.
pub(crate) async fn handle_verify_attestation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let committer = params
        .get("committer")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("Missing 'committer'"))?;
    let committer_bytes = hex::decode(committer.strip_prefix("0x").unwrap_or(committer))
        .map_err(|e| bad(format!("committer: {e}")))?;
    let epoch = params
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("Missing 'epoch'"))?;
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Chain state unavailable".to_string(),
        data: None,
    })?;
    let record =
        tenzro_vm::native::read_agent_audit(&chain, &committer_bytes, epoch).ok_or_else(|| {
            JsonRpcError {
                code: -32000,
                message: "no commitment is recorded for this account and epoch".to_string(),
                data: None,
            }
        })?;
    let attestation =
        hex::decode(&record.attestation).map_err(|e| bad(format!("attestation: {e}")))?;
    let verdict =
        verify_attestation(epoch, &record.root, &attestation).map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("the attestation does not verify: {e}"),
            data: None,
        })?;
    Ok(json!({
        "committer": format!("0x{}", hex::encode(&committer_bytes)),
        "epoch": epoch,
        "root": record.root,
        "sessions": record.sessions,
        "attestation": verdict,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::agent_audit::{SessionLeaf, epoch_root};

    fn line(session: u8, root: u8, count: u64) -> SessionLeaf {
        SessionLeaf {
            session_id: [session; 32],
            mmr_root: [root; 32],
            count,
        }
    }

    #[test]
    fn each_ended_epoch_is_due_once_with_each_sessions_latest_line() {
        let book = EpochBook::default();
        book.record(4, line(2, 1, 1)).unwrap();
        book.record(4, line(1, 1, 3)).unwrap();
        book.record(4, line(2, 2, 5)).unwrap();
        book.record(5, line(1, 3, 4)).unwrap();

        // Nothing is due while its epoch runs.
        assert!(book.due(4, |_| false).0.is_empty());
        let (due, lapsed) = book.due(5, |_| false);
        assert!(lapsed.is_empty());
        assert_eq!(
            due,
            vec![(4, vec![line(1, 1, 3), line(2, 2, 5)])],
            "ordered by session, latest line each"
        );

        // A commitment already on chain is not sent again.
        let (due, _) = book.due(6, |e| e == 4);
        assert_eq!(due.iter().map(|(e, _)| *e).collect::<Vec<_>>(), vec![5]);
        book.committed(5);
        assert!(book.due(6, |_| false).0.is_empty());
    }

    #[test]
    fn a_session_log_only_grows() {
        let book = EpochBook::default();
        book.record(1, line(1, 1, 3)).unwrap();
        assert!(
            book.record(2, line(1, 9, 2)).is_err(),
            "fewer entries than already reported"
        );
        assert!(
            book.record(2, line(1, 9, 3)).is_err(),
            "another root over as many entries"
        );
        assert!(book.record(2, line(1, 1, 3)).is_ok(), "the same line again");
        assert!(book.record(2, line(3, 1, 0)).is_err(), "an empty session");
    }

    #[test]
    fn an_epoch_past_the_commit_window_is_dropped_not_sent() {
        let book = EpochBook::default();
        book.record(1, line(1, 1, 1)).unwrap();
        let current = 2 + tenzro_vm::native::AGENT_AUDIT_COMMIT_WINDOW;
        let (due, lapsed) = book.due(current, |_| false);
        assert!(due.is_empty());
        assert_eq!(lapsed, vec![1]);
    }

    #[test]
    fn the_commitment_carries_the_epoch_root_over_the_lines() {
        let lines = vec![line(1, 1, 3), line(2, 2, 5)];
        let tenzro_types::TransactionType::AgentAuditCommit {
            epoch,
            root,
            sessions,
            entries_ref,
            attestation,
        } = commit_transaction(7, &lines, vec![1, 2])
        else {
            panic!("not an AgentAuditCommit");
        };
        assert_eq!(
            (epoch, sessions, entries_ref.as_str(), attestation),
            (7, 2, "", vec![1, 2])
        );
        assert_eq!(root, epoch_root(&lines).to_vec());
    }
}
